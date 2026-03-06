"""Comprehensive edge-case tests for PhaseDAGRunner, PhaseStep, and ArtifactStore."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from nocturna_engine.core.pipeline import ArtifactStore, PhaseDAGRunner, PhaseStep, PhaseStepStatus
from nocturna_engine.core.pipeline.types import PipelineContext
from nocturna_engine.exceptions import NocturnaTimeoutError, PipelineError


# ---------------------------------------------------------------------------
# Stubs / helpers
# ---------------------------------------------------------------------------


class _EventBusStub:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def publish(self, event_name: str, payload: dict[str, Any]) -> None:
        self.events.append((event_name, dict(payload)))


class _BrokenEventBus:
    """Event bus whose publish always raises."""

    async def publish(self, event_name: str, payload: dict[str, Any]) -> None:
        raise RuntimeError("event bus exploded")


class _NonCallableEventBus:
    """Event bus with a non-callable publish attribute."""
    publish = "not callable"


async def _ok_handler(step: PhaseStep, ctx: PipelineContext) -> PipelineContext:
    return {f"ran_{step.id}": True}


async def _noop_handler(_step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
    return {}


# ===========================================================================
# Empty DAG
# ===========================================================================


async def test_empty_dag_returns_default_metadata() -> None:
    runner = PhaseDAGRunner()
    result = await runner.run([], tool_handler=_noop_handler)
    assert result["dag_step_status"] == {}
    assert result["dag_phase_status"] == {}
    assert result["dag_skip_reasons"] == {}
    assert result["errors"] == []


async def test_empty_dag_preserves_initial_context() -> None:
    runner = PhaseDAGRunner()
    result = await runner.run([], tool_handler=_noop_handler, initial_context={"seed": 42})
    assert result["seed"] == 42


# ===========================================================================
# Single-step DAG
# ===========================================================================


async def test_single_step_dag() -> None:
    runner = PhaseDAGRunner()
    result = await runner.run(
        [PhaseStep(id="recon.nmap", phase="recon", tool="nmap")],
        tool_handler=_ok_handler,
    )
    assert result["ran_recon.nmap"] is True
    assert result["dag_step_status"]["recon.nmap"] == "succeeded"
    assert result["dag_phase_status"]["recon"] == "succeeded"


# ===========================================================================
# Linear dependency chain
# ===========================================================================


async def test_linear_chain_executes_in_order() -> None:
    runner = PhaseDAGRunner()
    order: list[str] = []

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        order.append(step.id)
        return {}

    steps = [
        PhaseStep(id="a", phase="p1", tool="t1"),
        PhaseStep(id="b", phase="p2", tool="t2", deps=("a",)),
        PhaseStep(id="c", phase="p3", tool="t3", deps=("b",)),
    ]
    await runner.run(steps, tool_handler=handler)
    assert order == ["a", "b", "c"]


async def test_steps_out_of_insertion_order_resolved_by_deps() -> None:
    """Steps listed in reverse still execute in dependency order."""
    runner = PhaseDAGRunner()
    order: list[str] = []

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        order.append(step.id)
        return {}

    steps = [
        PhaseStep(id="c", phase="p3", tool="t3", deps=("b",)),
        PhaseStep(id="b", phase="p2", tool="t2", deps=("a",)),
        PhaseStep(id="a", phase="p1", tool="t1"),
    ]
    await runner.run(steps, tool_handler=handler)
    assert order == ["a", "b", "c"]


# ===========================================================================
# Diamond dependency
# ===========================================================================


async def test_diamond_dependency_pattern() -> None:
    """
    A → B
    A → C
    B, C → D
    """
    runner = PhaseDAGRunner()
    order: list[str] = []

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        order.append(step.id)
        return {}

    steps = [
        PhaseStep(id="A", phase="recon", tool="a"),
        PhaseStep(id="B", phase="enrich", tool="b", deps=("A",)),
        PhaseStep(id="C", phase="enrich", tool="c", deps=("A",)),
        PhaseStep(id="D", phase="validate", tool="d", deps=("B", "C")),
    ]
    result = await runner.run(steps, tool_handler=handler)
    assert order.index("A") < order.index("B")
    assert order.index("A") < order.index("C")
    assert order.index("B") < order.index("D")
    assert order.index("C") < order.index("D")
    assert result["dag_step_status"]["D"] == "succeeded"


# ===========================================================================
# Cycle detection
# ===========================================================================


async def test_cycle_two_nodes_raises() -> None:
    runner = PhaseDAGRunner()
    steps = [
        PhaseStep(id="x", phase="p", tool="t", deps=("y",)),
        PhaseStep(id="y", phase="p", tool="t", deps=("x",)),
    ]
    with pytest.raises(PipelineError, match="Cycle detected"):
        await runner.run(steps, tool_handler=_noop_handler)


async def test_cycle_three_nodes_raises() -> None:
    runner = PhaseDAGRunner()
    steps = [
        PhaseStep(id="a", phase="p", tool="t", deps=("c",)),
        PhaseStep(id="b", phase="p", tool="t", deps=("a",)),
        PhaseStep(id="c", phase="p", tool="t", deps=("b",)),
    ]
    with pytest.raises(PipelineError, match="Cycle detected"):
        await runner.run(steps, tool_handler=_noop_handler)


async def test_self_referencing_step_raises() -> None:
    runner = PhaseDAGRunner()
    steps = [
        PhaseStep(id="self", phase="p", tool="t", deps=("self",)),
    ]
    with pytest.raises(PipelineError, match="Cycle detected"):
        await runner.run(steps, tool_handler=_noop_handler)


# ===========================================================================
# Duplicate step IDs
# ===========================================================================


async def test_duplicate_step_ids_raises() -> None:
    runner = PhaseDAGRunner()
    steps = [
        PhaseStep(id="dup", phase="p1", tool="t1"),
        PhaseStep(id="dup", phase="p2", tool="t2"),
    ]
    with pytest.raises(PipelineError, match="Duplicate phase step ids"):
        await runner.run(steps, tool_handler=_noop_handler)


# ===========================================================================
# Unknown dependency
# ===========================================================================


async def test_unknown_dependency_raises() -> None:
    runner = PhaseDAGRunner()
    steps = [
        PhaseStep(id="a", phase="p", tool="t", deps=("nonexistent",)),
    ]
    with pytest.raises(PipelineError, match="unknown dependencies"):
        await runner.run(steps, tool_handler=_noop_handler)


# ===========================================================================
# Step failure propagation
# ===========================================================================


async def test_failed_step_causes_dependents_to_skip() -> None:
    runner = PhaseDAGRunner()

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        if step.id == "fail":
            raise RuntimeError("boom")
        return {}

    steps = [
        PhaseStep(id="fail", phase="p1", tool="t1", retries=0),
        PhaseStep(id="child", phase="p2", tool="t2", deps=("fail",)),
        PhaseStep(id="grandchild", phase="p3", tool="t3", deps=("child",)),
    ]
    result = await runner.run(steps, tool_handler=handler)
    assert result["dag_step_status"]["fail"] == "failed"
    assert result["dag_step_status"]["child"] == "skipped"
    assert result["dag_step_status"]["grandchild"] == "skipped"


async def test_failure_records_error_in_context() -> None:
    runner = PhaseDAGRunner()

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        raise ValueError("step error detail")

    steps = [PhaseStep(id="err", phase="p", tool="t", retries=0)]
    result = await runner.run(steps, tool_handler=handler)
    assert len(result["errors"]) == 1
    assert result["errors"][0]["step"] == "err"
    assert "step error detail" in result["errors"][0]["error"]


async def test_failure_skip_reasons_populated() -> None:
    runner = PhaseDAGRunner()

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        if step.id == "root":
            raise RuntimeError("root broke")
        return {}

    steps = [
        PhaseStep(id="root", phase="p1", tool="t1", retries=0),
        PhaseStep(id="dep", phase="p2", tool="t2", deps=("root",)),
    ]
    result = await runner.run(steps, tool_handler=handler)
    assert "dep" in result["dag_skip_reasons"]
    assert "dependency_failed_or_skipped" in result["dag_skip_reasons"]["dep"]


async def test_independent_branch_runs_despite_sibling_failure() -> None:
    """Failure in one branch doesn't affect independent branches."""
    runner = PhaseDAGRunner()
    order: list[str] = []

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        order.append(step.id)
        if step.id == "fail_branch":
            raise RuntimeError("branch down")
        return {}

    steps = [
        PhaseStep(id="root", phase="p1", tool="t"),
        PhaseStep(id="fail_branch", phase="p2", tool="t", deps=("root",), retries=0),
        PhaseStep(id="ok_branch", phase="p3", tool="t", deps=("root",)),
        PhaseStep(id="child_of_fail", phase="p4", tool="t", deps=("fail_branch",)),
    ]
    result = await runner.run(steps, tool_handler=handler)
    assert "ok_branch" in order
    assert result["dag_step_status"]["ok_branch"] == "succeeded"
    assert result["dag_step_status"]["child_of_fail"] == "skipped"


# ===========================================================================
# Timeout in DAG step
# ===========================================================================


async def test_step_timeout_marks_as_failed() -> None:
    runner = PhaseDAGRunner()

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        await asyncio.sleep(10)
        return {}

    steps = [PhaseStep(id="slow", phase="p", tool="t", timeout_seconds=0.05, retries=0)]
    result = await runner.run(steps, tool_handler=handler)
    assert result["dag_step_status"]["slow"] == "failed"
    assert len(result["errors"]) == 1


# ===========================================================================
# Retry in DAG step
# ===========================================================================


async def test_step_retries_then_succeeds() -> None:
    runner = PhaseDAGRunner()
    attempts = 0

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise ConnectionError("transient")
        return {"recovered": True}

    steps = [PhaseStep(id="flaky", phase="p", tool="t", retries=2)]
    result = await runner.run(steps, tool_handler=handler)
    assert result["dag_step_status"]["flaky"] == "succeeded"
    assert result["recovered"] is True
    assert attempts == 2


async def test_step_retries_exhausted_marks_failed() -> None:
    runner = PhaseDAGRunner()
    attempts = 0

    async def handler(_step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        nonlocal attempts
        attempts += 1
        raise ConnectionError("permanent")

    steps = [PhaseStep(id="perm", phase="p", tool="t", retries=1)]
    result = await runner.run(steps, tool_handler=handler)
    assert result["dag_step_status"]["perm"] == "failed"
    assert attempts == 2  # initial + 1 retry


# ===========================================================================
# Step returning None / non-dict
# ===========================================================================


async def test_step_returning_none_treated_as_empty_dict() -> None:
    runner = PhaseDAGRunner()

    async def handler(_step: PhaseStep, _ctx: PipelineContext) -> None:
        return None

    steps = [PhaseStep(id="none_step", phase="p", tool="t")]
    result = await runner.run(steps, tool_handler=handler)
    assert result["dag_step_status"]["none_step"] == "succeeded"


async def test_step_returning_non_dict_raises_pipeline_error() -> None:
    runner = PhaseDAGRunner()

    async def handler(_step: PhaseStep, _ctx: PipelineContext) -> Any:
        return ["bad", "return"]

    steps = [PhaseStep(id="bad", phase="p", tool="t", retries=0)]
    result = await runner.run(steps, tool_handler=handler)
    # PipelineError is caught as BaseException, step marked failed
    assert result["dag_step_status"]["bad"] == "failed"
    assert any("must return dict or None" in e["error"] for e in result["errors"])


# ===========================================================================
# ArtifactStore
# ===========================================================================


async def test_artifact_store_put_and_get() -> None:
    store = ArtifactStore()
    key = store.put("recon", "nmap", "hosts", ["localhost"])
    assert key == "recon.nmap.hosts"


async def test_artifact_store_get_existing() -> None:
    store = ArtifactStore()
    store.put("recon", "nmap", "hosts", ["h1", "h2"])
    assert store.get("recon.nmap.hosts") == ["h1", "h2"]


async def test_artifact_store_get_missing_returns_default() -> None:
    store = ArtifactStore()
    assert store.get("no.such.key") is None
    assert store.get("no.such.key", "fallback") == "fallback"


async def test_artifact_store_key_normalization() -> None:
    store = ArtifactStore()
    store.put("  RECON ", " Nmap ", " HOSTS ", "value")
    assert store.get("recon.nmap.hosts") is not None


async def test_artifact_store_get_normalizes_key() -> None:
    store = ArtifactStore()
    store.put("recon", "nmap", "hosts", 42)
    assert store.get("  RECON.NMAP.HOSTS  ") == 42


async def test_artifact_store_empty_part_raises() -> None:
    store = ArtifactStore()
    with pytest.raises(ValueError, match="non-empty"):
        store.put("", "tool", "key", "v")
    with pytest.raises(ValueError, match="non-empty"):
        store.put("phase", "", "key", "v")
    with pytest.raises(ValueError, match="non-empty"):
        store.put("phase", "tool", "", "v")


@pytest.mark.parametrize("phase,tool,key", [
    ("  ", "tool", "key"),
    ("phase", "   ", "key"),
    ("phase", "tool", "   "),
])
async def test_artifact_store_whitespace_only_part_raises(phase: str, tool: str, key: str) -> None:
    store = ArtifactStore()
    with pytest.raises(ValueError, match="non-empty"):
        store.put(phase, tool, key, "v")


async def test_artifact_store_build_key_static() -> None:
    assert ArtifactStore.build_key("Recon", "Nmap", "Hosts") == "recon.nmap.hosts"


async def test_artifact_store_list_all() -> None:
    store = ArtifactStore()
    store.put("recon", "nmap", "hosts", 1)
    store.put("recon", "nmap", "ports", 2)
    store.put("enrich", "whois", "data", 3)
    keys = store.list()
    assert keys == ["enrich.whois.data", "recon.nmap.hosts", "recon.nmap.ports"]


async def test_artifact_store_list_with_prefix() -> None:
    store = ArtifactStore()
    store.put("recon", "nmap", "hosts", 1)
    store.put("recon", "nmap", "ports", 2)
    store.put("enrich", "whois", "data", 3)
    assert store.list("recon") == ["recon.nmap.hosts", "recon.nmap.ports"]
    assert store.list("enrich") == ["enrich.whois.data"]


async def test_artifact_store_list_empty() -> None:
    store = ArtifactStore()
    assert store.list() == []
    assert store.list("recon") == []


async def test_artifact_store_overwrite() -> None:
    store = ArtifactStore()
    store.put("p", "t", "k", "old")
    store.put("p", "t", "k", "new")
    assert store.get("p.t.k") == "new"


# ===========================================================================
# Artifact flow through DAG context
# ===========================================================================


async def test_artifact_store_injected_into_context() -> None:
    runner = PhaseDAGRunner()

    async def handler(_step: PhaseStep, ctx: PipelineContext) -> PipelineContext:
        assert isinstance(ctx["artifacts"], ArtifactStore)
        return {}

    steps = [PhaseStep(id="check", phase="p", tool="t")]
    await runner.run(steps, tool_handler=handler)


async def test_artifact_store_preserved_from_initial_context() -> None:
    runner = PhaseDAGRunner()
    existing_store = ArtifactStore()
    existing_store.put("pre", "existing", "data", "preserved")

    async def handler(_step: PhaseStep, ctx: PipelineContext) -> PipelineContext:
        store = ctx["artifacts"]
        assert store.get("pre.existing.data") == "preserved"
        return {}

    steps = [PhaseStep(id="check", phase="p", tool="t")]
    await runner.run(steps, tool_handler=handler, initial_context={"artifacts": existing_store})


async def test_artifact_data_flows_between_steps() -> None:
    runner = PhaseDAGRunner()

    async def handler(step: PhaseStep, ctx: PipelineContext) -> PipelineContext:
        store: ArtifactStore = ctx["artifacts"]
        if step.id == "producer":
            store.put("recon", "nmap", "targets", ["10.0.0.1"])
        elif step.id == "consumer":
            targets = store.get("recon.nmap.targets")
            return {"consumed_targets": targets}
        return {}

    steps = [
        PhaseStep(id="producer", phase="recon", tool="nmap"),
        PhaseStep(id="consumer", phase="enrich", tool="whois", deps=("producer",)),
    ]
    result = await runner.run(steps, tool_handler=handler)
    assert result["consumed_targets"] == ["10.0.0.1"]


# ===========================================================================
# Event bus integration
# ===========================================================================


async def test_event_bus_emits_phase_started_and_finished() -> None:
    bus = _EventBusStub()
    runner = PhaseDAGRunner(event_bus=bus)

    steps = [PhaseStep(id="s1", phase="recon", tool="nmap")]
    await runner.run(steps, tool_handler=_ok_handler)

    event_names = [name for name, _ in bus.events]
    assert "on_phase_started" in event_names
    assert "on_phase_finished" in event_names


async def test_event_bus_emits_phase_failed_on_step_failure() -> None:
    bus = _EventBusStub()
    runner = PhaseDAGRunner(event_bus=bus)

    async def handler(_step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        raise RuntimeError("kaboom")

    steps = [PhaseStep(id="s1", phase="recon", tool="nmap", retries=0)]
    await runner.run(steps, tool_handler=handler)

    event_names = [name for name, _ in bus.events]
    assert "on_phase_failed" in event_names


async def test_event_bus_failure_does_not_crash_runner() -> None:
    """Broken event bus should not prevent DAG execution."""
    runner = PhaseDAGRunner(event_bus=_BrokenEventBus())

    steps = [PhaseStep(id="s1", phase="recon", tool="nmap")]
    result = await runner.run(steps, tool_handler=_ok_handler)
    assert result["dag_step_status"]["s1"] == "succeeded"


async def test_non_callable_event_bus_publish_ignored() -> None:
    runner = PhaseDAGRunner(event_bus=_NonCallableEventBus())
    steps = [PhaseStep(id="s1", phase="recon", tool="nmap")]
    result = await runner.run(steps, tool_handler=_ok_handler)
    assert result["dag_step_status"]["s1"] == "succeeded"


async def test_no_event_bus_still_works() -> None:
    runner = PhaseDAGRunner(event_bus=None)
    steps = [PhaseStep(id="s1", phase="recon", tool="nmap")]
    result = await runner.run(steps, tool_handler=_ok_handler)
    assert result["dag_step_status"]["s1"] == "succeeded"


async def test_event_payload_includes_phase() -> None:
    bus = _EventBusStub()
    runner = PhaseDAGRunner(event_bus=bus)

    steps = [PhaseStep(id="s1", phase="recon", tool="nmap")]
    await runner.run(steps, tool_handler=_ok_handler)

    for _name, payload in bus.events:
        assert "phase" in payload


# ===========================================================================
# PhaseStep validation
# ===========================================================================


async def test_phase_step_empty_id_raises() -> None:
    with pytest.raises(ValueError, match="id cannot be empty"):
        PhaseStep(id="", phase="p", tool="t")


async def test_phase_step_empty_phase_raises() -> None:
    with pytest.raises(ValueError, match="phase cannot be empty"):
        PhaseStep(id="s", phase="", tool="t")


async def test_phase_step_empty_tool_raises() -> None:
    with pytest.raises(ValueError, match="tool cannot be empty"):
        PhaseStep(id="s", phase="p", tool="")


async def test_phase_step_whitespace_only_id_raises() -> None:
    with pytest.raises(ValueError, match="id cannot be empty"):
        PhaseStep(id="   ", phase="p", tool="t")


async def test_phase_step_strips_and_lowercases() -> None:
    step = PhaseStep(id="  MyStep  ", phase="  RECON  ", tool="  NMAP  ")
    assert step.id == "MyStep"  # id is stripped but not lowered
    assert step.phase == "recon"
    assert step.tool == "nmap"


async def test_phase_step_deduplicates_deps() -> None:
    step = PhaseStep(id="s", phase="p", tool="t", deps=("a", "a", "b", "a"))
    assert step.deps == ("a", "b")


async def test_phase_step_strips_deps() -> None:
    step = PhaseStep(id="s", phase="p", tool="t", deps=("  a  ", " b "))
    assert step.deps == ("a", "b")


async def test_phase_step_filters_empty_deps() -> None:
    step = PhaseStep(id="s", phase="p", tool="t", deps=("a", "", "  ", "b"))
    assert step.deps == ("a", "b")


async def test_phase_step_retries_clamp_negative() -> None:
    step = PhaseStep(id="s", phase="p", tool="t", retries=-5)
    assert step.retries == 0


async def test_phase_step_defaults() -> None:
    step = PhaseStep(id="s", phase="p", tool="t")
    assert step.deps == ()
    assert step.timeout_seconds == 60.0
    assert step.retries == 1


# ===========================================================================
# Phase status aggregation
# ===========================================================================


async def test_phase_all_succeeded() -> None:
    runner = PhaseDAGRunner()
    steps = [
        PhaseStep(id="s1", phase="recon", tool="a"),
        PhaseStep(id="s2", phase="recon", tool="b"),
    ]
    result = await runner.run(steps, tool_handler=_ok_handler)
    assert result["dag_phase_status"]["recon"] == "succeeded"


async def test_phase_mixed_fail_and_success_marks_failed() -> None:
    runner = PhaseDAGRunner()

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        if step.id == "s2":
            raise RuntimeError("fail")
        return {}

    steps = [
        PhaseStep(id="s1", phase="recon", tool="a"),
        PhaseStep(id="s2", phase="recon", tool="b", retries=0),
    ]
    result = await runner.run(steps, tool_handler=handler)
    assert result["dag_phase_status"]["recon"] == "failed"


async def test_phase_all_skipped() -> None:
    runner = PhaseDAGRunner()

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        if step.id == "root":
            raise RuntimeError("fail")
        return {}

    steps = [
        PhaseStep(id="root", phase="p1", tool="t", retries=0),
        PhaseStep(id="skip1", phase="p2", tool="t", deps=("root",)),
        PhaseStep(id="skip2", phase="p2", tool="t", deps=("root",)),
    ]
    result = await runner.run(steps, tool_handler=handler)
    assert result["dag_phase_status"]["p2"] == "skipped"


# ===========================================================================
# Context merging
# ===========================================================================


async def test_step_context_update_merges_into_shared_context() -> None:
    runner = PhaseDAGRunner()

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        if step.id == "a":
            return {"x": 1}
        if step.id == "b":
            return {"y": 2}
        return {}

    steps = [
        PhaseStep(id="a", phase="p1", tool="t"),
        PhaseStep(id="b", phase="p2", tool="t", deps=("a",)),
    ]
    result = await runner.run(steps, tool_handler=handler)
    assert result["x"] == 1
    assert result["y"] == 2


async def test_later_step_can_overwrite_context_key() -> None:
    runner = PhaseDAGRunner()

    async def handler(step: PhaseStep, _ctx: PipelineContext) -> PipelineContext:
        if step.id == "a":
            return {"val": "first"}
        return {"val": "second"}

    steps = [
        PhaseStep(id="a", phase="p1", tool="t"),
        PhaseStep(id="b", phase="p2", tool="t", deps=("a",)),
    ]
    result = await runner.run(steps, tool_handler=handler)
    assert result["val"] == "second"
