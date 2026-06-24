"""Optional live-cluster scanning via the kubernetes client.

This module degrades gracefully: if the ``kubernetes`` package is not installed
or no cluster/kubeconfig is reachable, it returns a clear, non-fatal error
instead of raising. The CLI surfaces that message and exits cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Resource


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
    except Exception as exc:
        raise ClusterScanError(f"Failed while reading cluster resources: {exc}") from exc

    return ClusterResources(resources=tuple(resources), context=active_context)


def _collect_workloads(apps, core, resources: list[Resource]) -> None:  # type: ignore[no-untyped-def]
    for item in apps.list_deployment_for_all_namespaces().items:
        resources.append(_to_resource("Deployment", "apps/v1", _to_dict(item), None))
    for item in apps.list_daemon_set_for_all_namespaces().items:
        resources.append(_to_resource("DaemonSet", "apps/v1", _to_dict(item), None))
    for item in apps.list_stateful_set_for_all_namespaces().items:
        resources.append(_to_resource("StatefulSet", "apps/v1", _to_dict(item), None))
    for item in core.list_pod_for_all_namespaces().items:
        resources.append(_to_resource("Pod", "v1", _to_dict(item), None))


def _collect_rbac(rbac, resources: list[Resource]) -> None:  # type: ignore[no-untyped-def]
    for item in rbac.list_role_for_all_namespaces().items:
        resources.append(_to_resource("Role", "rbac.authorization.k8s.io/v1", _to_dict(item), None))
    for item in rbac.list_cluster_role().items:
        resources.append(
            _to_resource("ClusterRole", "rbac.authorization.k8s.io/v1", _to_dict(item), None)
        )
    for item in rbac.list_cluster_role_binding().items:
        resources.append(
            _to_resource("ClusterRoleBinding", "rbac.authorization.k8s.io/v1", _to_dict(item), None)
        )


def _collect_networking(core, networking, resources: list[Resource]) -> None:  # type: ignore[no-untyped-def]
    for item in core.list_service_for_all_namespaces().items:
        resources.append(_to_resource("Service", "v1", _to_dict(item), None))
    for item in networking.list_network_policy_for_all_namespaces().items:
        resources.append(
            _to_resource("NetworkPolicy", "networking.k8s.io/v1", _to_dict(item), None)
        )


def _to_dict(obj: object) -> dict:
    """Convert a kubernetes client model to a plain camelCase dict.

    The client's serialization uses the API (camelCase) field names, which is
    exactly the shape our rules expect from YAML manifests.
    """
    from kubernetes.client import ApiClient

    result = ApiClient().sanitize_for_serialization(obj)
    return result if isinstance(result, dict) else {}
