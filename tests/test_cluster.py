"""Live-cluster collection: the cases where a scan must refuse to report.

``tests/test_cluster_parity.py`` establishes that the shape handed to the engine
is right. This module covers the other half: what happens when the collection
itself is incomplete. A posture scanner that reads part of a cluster, or none of
it, and then prints a score has not failed safely — it has reported a clean bill
of health it never earned. Each test here pins a path that must raise rather
than return.

The API objects are faked. These tests are about the collection loop's control
flow, not about the client's HTTP behaviour, and a fake is the only way to drive
a continue token or a serialisation failure deterministically.
"""

from __future__ import annotations

from typing import Any

import pytest

from kube_sentinel.cluster import (
    MAX_PAGES,
    ClusterScanError,
    _collect_networking,
    _collect_rbac,
    _collect_workloads,
    _list_all,
    _to_dict,
)
from kube_sentinel.models import Resource


class _FakeMeta:
    """Stands in for V1ListMeta, whose continue token is the ``_continue`` attr."""

    def __init__(self, token: str | None) -> None:
        self._continue = token


class _FakeList:
    def __init__(self, items: list[Any], token: str | None = None) -> None:
        self.items = items
        self.metadata = _FakeMeta(token)


class _PagedLister:
    """A list endpoint that answers in pages, as a chunking apiserver does."""

    def __init__(self, pages: list[_FakeList]) -> None:
        self._pages = pages
        self.calls: list[str | None] = []

    def __call__(self, **kwargs: Any) -> _FakeList:
        token = kwargs.get("_continue")
        self.calls.append(token)
        index = 0 if token is None else int(token)
        return self._pages[index]


def _named(name: str) -> Any:
    """A minimal object that serialises to a Kubernetes-shaped dict."""
    return {"metadata": {"name": name, "namespace": "demo"}}


# --- Pagination ------------------------------------------------------------


def test_list_all_follows_the_continue_token() -> None:
    """Every page must be collected, not just the first."""
    lister = _PagedLister(
        [
            _FakeList([_named("a"), _named("b")], token="1"),
            _FakeList([_named("c")], token=None),
        ]
    )

    items = _list_all(lister)

    assert [i["metadata"]["name"] for i in items] == ["a", "b", "c"]
    assert lister.calls == [None, "1"]


def test_list_all_asks_for_bounded_pages() -> None:
    """The request must carry a limit, so one huge response cannot be the plan."""
    lister = _PagedLister([_FakeList([_named("a")], token=None)])

    _list_all(lister)

    # Recorded via a second call that inspects kwargs directly.
    seen: dict[str, Any] = {}

    def recording(**kwargs: Any) -> _FakeList:
        seen.update(kwargs)
        return _FakeList([], token=None)

    _list_all(recording)
    assert isinstance(seen.get("limit"), int)
    assert seen["limit"] > 0


def test_list_all_refuses_an_endless_continue_token() -> None:
    """A server that never stops handing back a token must not hang the scan.

    Raising beats looping forever: a hung scan is indistinguishable from a slow
    one, and the operator gets no signal either way.
    """

    def never_ends(**kwargs: Any) -> _FakeList:
        return _FakeList([_named("x")], token="0")

    with pytest.raises(ClusterScanError, match="too many pages"):
        _list_all(never_ends)


def test_collectors_paginate_every_endpoint() -> None:
    """All nine endpoints go through the paging loop, not a bare single call.

    Enumerated rather than spot-checked because a new collector added without
    the loop would be the same silent-truncation bug again.
    """

    class _Api:
        """Answers any list_* call with two pages, recording which were paged."""

        def __init__(self) -> None:
            self.paged: set[str] = set()

        def __getattr__(self, name: str) -> Any:
            if not name.startswith("list_"):
                raise AttributeError(name)

            def lister(**kwargs: Any) -> _FakeList:
                if kwargs.get("_continue") is None:
                    return _FakeList([_named(f"{name}-p1")], token="1")
                self.paged.add(name)
                return _FakeList([_named(f"{name}-p2")], token=None)

            return lister

    api = _Api()
    resources: list[Resource] = []
    _collect_workloads(api, api, resources)
    _collect_rbac(api, resources)
    _collect_networking(api, api, resources)

    # Nine endpoints, two pages each.
    assert len(api.paged) == 9
    assert len(resources) == 18


# --- Loud failure instead of an empty scan --------------------------------


def test_to_dict_raises_when_serialisation_is_not_an_object() -> None:
    """An unserialisable object must abort, not become an empty resource.

    Returning ``{}`` here would hand the engine a resource with no fields. Every
    rule would find nothing wrong with it and the scan would report success for
    an object it never actually read.
    """
    with pytest.raises(ClusterScanError, match="serialise"):
        _to_dict(["not", "an", "object"])


def test_max_pages_is_bounded() -> None:
    """The page ceiling is a real bound, not an accidental None."""
    assert isinstance(MAX_PAGES, int)
    assert MAX_PAGES > 0


class _EmptyApi:
    """Every list endpoint answers with nothing — the shape of a scoped scan."""

    def __getattr__(self, name: str) -> Any:
        if not name.startswith("list_"):
            raise AttributeError(name)
        return lambda **kwargs: _FakeList([], token=None)


class _FakeClient:
    AppsV1Api = _EmptyApi
    CoreV1Api = _EmptyApi
    RbacAuthorizationV1Api = _EmptyApi
    NetworkingV1Api = _EmptyApi


class _FakeConfig:
    @staticmethod
    def load_kube_config(context: str | None = None) -> None:
        return None

    @staticmethod
    def list_kube_config_contexts() -> tuple[Any, dict[str, str]]:
        return ([], {"name": "fake-context"})


def test_a_scan_that_collected_nothing_refuses_to_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero resources is a broken scan, not a perfect cluster.

    No reachable cluster is actually empty — kube-system alone guarantees pods.
    Zero collected resources means the scan did not see the cluster: a
    ServiceAccount scoped to a namespace it cannot list, the wrong context, or a
    proxy answering with empty lists. Scoring that as 100/A+ is the worst
    outcome available, because it is indistinguishable from good news.
    """
    from kube_sentinel import cluster as cluster_mod

    monkeypatch.setattr(cluster_mod, "_import_kubernetes", lambda: (_FakeClient, _FakeConfig))

    with pytest.raises(ClusterScanError, match="no resources"):
        cluster_mod.fetch_cluster_resources()
