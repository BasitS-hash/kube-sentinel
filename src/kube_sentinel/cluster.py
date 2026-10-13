"""Optional live-cluster scanning via the kubernetes client.

Every recoverable problem surfaces as a ``ClusterScanError`` carrying a message
meant for an operator. The CLI catches it, prints it, and exits 2, so a missing
client or an unreachable kubeconfig never crashes the process.

The harder requirement is the other direction: this module must not hand the
engine a resource set it could not fully read. The engine has no way to tell an
empty cluster from a scan that saw nothing, so it would score either as 100/A+ —
a clean exit code on a broken scan, which is worse than a crash because it is
indistinguishable from good news. Every path that cannot guarantee a complete,
interpretable read therefore raises rather than returning a short set: see
``_list_all`` (paging), ``_to_dict`` (serialisation) and the empty-result guard
in ``fetch_cluster_resources``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .models import Resource

# The apiserver answers an unbounded list in full, but on a large cluster that
# single response is the one most likely to be rejected or to time out. Asking
# for bounded pages avoids that — and once we ask for pages, following the
# continue token is mandatory rather than optional: a bounded list whose token
# we ignored would read only the first page and then print a posture score for
# the whole cluster.
PAGE_LIMIT = 500

# A ceiling on the paging loop. At PAGE_LIMIT per page this is 1,000,000
# objects, well past any real cluster, so hitting it means the server is handing
# back a token it should not. Raising beats looping: a hung scan looks exactly
# like a slow one, and the operator gets no signal either way.
MAX_PAGES = 2000


@dataclass(frozen=True)
class ClusterScanError(Exception):
    """A recoverable failure while talking to a cluster."""

    detail: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.detail


@dataclass(frozen=True)
class ClusterResources:
    """Resources fetched from a live cluster, with the context used."""

    resources: tuple[Resource, ...]
    context: str


def _import_kubernetes():  # type: ignore[no-untyped-def]
    """Import the kubernetes client, raising ClusterScanError if unavailable."""
    try:
        from kubernetes import client, config
    except ImportError as exc:  # pragma: no cover - exercised via CLI message
        raise ClusterScanError(
            "The 'kubernetes' client is not installed. Install the cluster "
            "extra: pip install 'kube-sentinel[cluster]'"
        ) from exc
    return client, config


def _list_all(list_fn: Callable[..., Any]) -> list[Any]:
    """Collect every page of a list endpoint, following the continue token.

    ``list_fn`` is one of the client's ``list_*`` methods. The token lives on
    ``metadata.continue``, which the generated models expose as ``_continue``.
    """
    items: list[Any] = []
    token: str | None = None

    for _ in range(MAX_PAGES):
        response = list_fn(limit=PAGE_LIMIT, _continue=token)
        items.extend(response.items or [])
        metadata = getattr(response, "metadata", None)
        token = getattr(metadata, "_continue", None) or None
        if token is None:
            return items

    raise ClusterScanError(
        f"The API server returned too many pages (over {MAX_PAGES}) for a single "
        "list call. Refusing to report a partial scan."
    )


def _to_resource(kind: str, api_version: str, obj: dict, namespace: str | None) -> Resource:
    metadata = obj.get("metadata", {}) or {}
    name = metadata.get("name", "<unnamed>")
    ns = metadata.get("namespace", namespace)
    # Ensure kind/apiVersion are present so rules and the parser shape agree.
    enriched = dict(obj)
    enriched.setdefault("kind", kind)
    enriched.setdefault("apiVersion", api_version)
    return Resource(
        kind=kind,
        name=name,
        namespace=ns,
        api_version=api_version,
        file_path=f"cluster://{kind}/{ns or 'cluster'}/{name}",
        doc_index=0,
        raw=enriched,
    )


def fetch_cluster_resources(
    context: str | None = None,
) -> ClusterResources:
    """Fetch workloads, RBAC, services, and netpols from the active cluster.

    Raises ClusterScanError on any recoverable problem (no kubeconfig, no
    connectivity, missing client). Never crashes the process.
    """
    client, config = _import_kubernetes()

    try:
        config.load_kube_config(context=context)
        active_context = config.list_kube_config_contexts()[1]["name"]
    except Exception:
        try:
            config.load_incluster_config()
            active_context = "in-cluster"
        except Exception as exc:
            raise ClusterScanError(
                "No reachable cluster: could not load a kubeconfig context or "
                "in-cluster config. Check 'kubectl config current-context'."
            ) from exc

    resources: list[Resource] = []
    apps = client.AppsV1Api()
    core = client.CoreV1Api()
    rbac = client.RbacAuthorizationV1Api()
    networking = client.NetworkingV1Api()

    try:
        _collect_workloads(apps, core, resources)
        _collect_rbac(rbac, resources)
        _collect_networking(core, networking, resources)
    except ClusterScanError:
        # Already a clear, actionable message — don't bury it in a wrapper.
        raise
    except Exception as exc:
        raise ClusterScanError(f"Failed while reading cluster resources: {exc}") from exc

    # A reachable cluster is never empty: kube-system alone guarantees pods. Zero
    # collected resources means the scan did not see the cluster — a
    # ServiceAccount scoped to namespaces it cannot list, the wrong context, or a
    # proxy answering with empty lists. Scoring that would print 100/A+, which is
    # the worst available outcome because it is indistinguishable from good news.
    if not resources:
        raise ClusterScanError(
            f"Read no resources from context '{active_context}'. A reachable "
            "cluster always has some, so this is a scoping or connectivity "
            "problem, not a clean cluster. Check that the credentials can list "
            "pods, RBAC, and services across namespaces."
        )

    return ClusterResources(resources=tuple(resources), context=active_context)


def _collect(
    list_fn: Callable[..., Any],
    kind: str,
    api_version: str,
    resources: list[Resource],
) -> None:
    """Page through one endpoint and append its objects as Resources."""
    for item in _list_all(list_fn):
        resources.append(_to_resource(kind, api_version, _to_dict(item), None))


_RBAC_V1 = "rbac.authorization.k8s.io/v1"


def _collect_workloads(apps, core, resources: list[Resource]) -> None:  # type: ignore[no-untyped-def]
    _collect(apps.list_deployment_for_all_namespaces, "Deployment", "apps/v1", resources)
    _collect(apps.list_daemon_set_for_all_namespaces, "DaemonSet", "apps/v1", resources)
    _collect(apps.list_stateful_set_for_all_namespaces, "StatefulSet", "apps/v1", resources)
    _collect(core.list_pod_for_all_namespaces, "Pod", "v1", resources)


def _collect_rbac(rbac, resources: list[Resource]) -> None:  # type: ignore[no-untyped-def]
    _collect(rbac.list_role_for_all_namespaces, "Role", _RBAC_V1, resources)
    _collect(rbac.list_cluster_role, "ClusterRole", _RBAC_V1, resources)
    _collect(rbac.list_cluster_role_binding, "ClusterRoleBinding", _RBAC_V1, resources)


def _collect_networking(core, networking, resources: list[Resource]) -> None:  # type: ignore[no-untyped-def]
    _collect(core.list_service_for_all_namespaces, "Service", "v1", resources)
    _collect(
        networking.list_network_policy_for_all_namespaces,
        "NetworkPolicy",
        "networking.k8s.io/v1",
        resources,
    )


def _to_dict(obj: object) -> dict:
    """Convert a kubernetes client model to a plain camelCase dict.

    ``sanitize_for_serialization`` emits the API (camelCase) field names and
    omits unset fields, which is exactly the shape the rules expect from YAML.
    Note that this is *not* ``to_dict()``: that returns the models' snake_case
    attribute names (``security_context``, ``host_network``), which no rule
    navigates. Swapping the two would make every rule find nothing on a live
    cluster without raising — see tests/test_cluster_parity.py.

    A result that is not a dict aborts the scan. Returning ``{}`` instead would
    hand the engine a resource with no fields: every rule would find nothing
    wrong with it, and the scan would report success for an object it never
    actually read.
    """
    from kubernetes.client import ApiClient

    result = ApiClient().sanitize_for_serialization(obj)
    if not isinstance(result, dict):
        raise ClusterScanError(
            f"Could not serialise a {type(obj).__name__} from the API into an "
            "object. Refusing to report a scan that skipped it."
        )
    return result
