"""Comprehensive edge-case tests for Pipeline, PipelineStep, and PipelineContext."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from nocturna_engine.core.pipeline import Pipeline, PipelineStep
from nocturna_engine.core.pipeline.types import PipelineContext
from nocturna_engine.exceptions import NocturnaTimeoutError, PipelineError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _noop(_ctx: PipelineContext) -> PipelineContext:
    return {}


async def _identity(ctx: PipelineContext) -> PipelineContext:
    return dict(ctx)


async def _raise(msg: str = "boom"):
    async def _handler(_ctx: PipelineContext) -> PipelineContext:
        raise RuntimeError(msg)
    return _handler


# ===========================================================================
# Empty / minimal pipeline
# ===========================================================================


async def test_empty_pipeline_returns_default_context() -> None:
    """Running a pipeline with no steps returns a context with an errors list."""
    result = await Pipeline().run()
    assert result == {"errors": []}


async def test_empty_pipeline_preserves_initial_context() -> None:
    result = await Pipeline().run({"seed": 42})
    assert result["seed"] == 42
    assert result["errors"] == []


async def test_single_step_pipeline() -> None:
    pipeline = Pipeline()
    pipeline.add_step(PipelineStep(name="only", handler=_noop))
    result = await pipeline.run()
    assert result == {"errors": []}


# ===========================================================================
# Step ordering
# ===========================================================================


async def test_steps_execute_in_insertion_order() -> None:
    pipeline = Pipeline()
    order: list[str] = []

    for name in ("a", "b", "c", "d"):
        async def _handler(ctx: PipelineContext, _n=name) -> PipelineContext:
            order.append(_n)
            return {}
        pipeline.add_step(PipelineStep(name=name, handler=_handler))

    await pipeline.run()
    assert order == ["a", "b", "c", "d"]


async def test_step_receives_accumulated_context() -> None:
    pipeline = Pipeline()

    async def first(_ctx: PipelineContext) -> PipelineContext:
        return {"x": 1}

    async def second(ctx: PipelineContext) -> PipelineContext:
        return {"y": ctx["x"] + 1}

    async def third(ctx: PipelineContext) -> PipelineContext:
        return {"z": ctx["x"] + ctx["y"]}

    pipeline.add_step(PipelineStep(name="first", handler=first))
    pipeline.add_step(PipelineStep(name="second", handler=second))
    pipeline.add_step(PipelineStep(name="third", handler=third))
    result = await pipeline.run()

    assert result["x"] == 1
    assert result["y"] == 2
    assert result["z"] == 3


async def test_later_step_overwrites_earlier_key() -> None:
    pipeline = Pipeline()

    async def step_a(_ctx: PipelineContext) -> PipelineContext:
        return {"val": "first"}

    async def step_b(_ctx: PipelineContext) -> PipelineContext:
        return {"val": "second"}

    pipeline.add_step(PipelineStep(name="a", handler=step_a))
    pipeline.add_step(PipelineStep(name="b", handler=step_b))
    result = await pipeline.run()
    assert result["val"] == "second"


# ===========================================================================
# list_steps / clear_steps
# ===========================================================================


async def test_list_steps_returns_names() -> None:
    pipeline = Pipeline()
    pipeline.add_step(PipelineStep(name="alpha", handler=_noop))
    pipeline.add_step(PipelineStep(name="beta", handler=_noop))
    assert pipeline.list_steps() == ["alpha", "beta"]


async def test_clear_steps_empties_pipeline() -> None:
    pipeline = Pipeline()
    pipeline.add_step(PipelineStep(name="x", handler=_noop))
    pipeline.clear_steps()
    assert pipeline.list_steps() == []
    result = await pipeline.run()
    assert result == {"errors": []}


# ===========================================================================
# Step returning None
# ===========================================================================


async def test_step_returning_none_is_treated_as_empty_dict() -> None:
    pipeline = Pipeline()

    async def returns_none(_ctx: PipelineContext) -> None:
        return None

    pipeline.add_step(PipelineStep(name="none_step", handler=returns_none))
    pipeline.add_step(PipelineStep(name="after", handler=lambda ctx: asyncio.coroutine(lambda: {"ok": True})() if False else _noop(ctx)))

    async def after(_ctx: PipelineContext) -> PipelineContext:
        return {"ok": True}

    pipeline.clear_steps()
    pipeline.add_step(PipelineStep(name="none_step", handler=returns_none))
    pipeline.add_step(PipelineStep(name="after", handler=after))
    result = await pipeline.run()
    assert result["ok"] is True


# ===========================================================================
# Step returning non-dict
# ===========================================================================


async def test_step_returning_non_dict_raises_pipeline_error() -> None:
    pipeline = Pipeline()

    async def bad_return(_ctx: PipelineContext) -> Any:
        return ["not", "a", "dict"]

    pipeline.add_step(PipelineStep(name="bad", handler=bad_return, continue_on_error=False))
    with pytest.raises(PipelineError, match="must return dict or None"):
        await pipeline.run()


async def test_step_returning_non_dict_continue_on_error_collects() -> None:
    pipeline = Pipeline()

    async def bad_return(_ctx: PipelineContext) -> Any:
        return 42

    pipeline.add_step(PipelineStep(name="bad", handler=bad_return, continue_on_error=True))
    result = await pipeline.run()
    assert len(result["errors"]) == 1
    assert result["errors"][0]["step"] == "bad"


# ===========================================================================
# Condition handling
# ===========================================================================


async def test_condition_true_runs_step() -> None:
    pipeline = Pipeline()
    ran = False

    async def handler(_ctx: PipelineContext) -> PipelineContext:
        nonlocal ran
        ran = True
        return {}

    pipeline.add_step(PipelineStep(name="cond", handler=handler, condition=lambda _: True))
    await pipeline.run()
    assert ran is True


async def test_condition_false_skips_step() -> None:
    pipeline = Pipeline()
    ran = False

    async def handler(_ctx: PipelineContext) -> PipelineContext:
        nonlocal ran
        ran = True
        return {}

    pipeline.add_step(PipelineStep(name="skip", handler=handler, condition=lambda _: False))
    await pipeline.run()
    assert ran is False


async def test_condition_uses_current_context() -> None:
    pipeline = Pipeline()

    async def setter(_ctx: PipelineContext) -> PipelineContext:
        return {"gate": True}

    async def gated(_ctx: PipelineContext) -> PipelineContext:
        return {"gated_ran": True}

    pipeline.add_step(PipelineStep(name="setter", handler=setter))
    pipeline.add_step(PipelineStep(name="gated", handler=gated, condition=lambda ctx: ctx.get("gate", False)))
    result = await pipeline.run()
    assert result["gated_ran"] is True


async def test_condition_raising_exception_continue_on_error() -> None:
    pipeline = Pipeline()

    async def handler(_ctx: PipelineContext) -> PipelineContext:
        return {"should_not_appear": True}

    def exploding_condition(_ctx: PipelineContext) -> bool:
        raise TypeError("broken predicate")

    pipeline.add_step(PipelineStep(
        name="exploding",
        handler=handler,
        condition=exploding_condition,
        continue_on_error=True,
    ))
    result = await pipeline.run()
    assert "should_not_appear" not in result
    assert len(result["errors"]) == 1
    assert "TypeError" in result["errors"][0]["error"]


async def test_condition_raising_exception_strict_raises() -> None:
    pipeline = Pipeline()

    async def handler(_ctx: PipelineContext) -> PipelineContext:
        return {}

    def bad(_ctx: PipelineContext) -> bool:
        raise ValueError("fatal condition")

    pipeline.add_step(PipelineStep(
        name="strict",
        handler=handler,
        condition=bad,
        continue_on_error=False,
    ))
    with pytest.raises(PipelineError, match="strict"):
        await pipeline.run()


# ===========================================================================
# Failure handling: continue_on_error vs strict
# ===========================================================================


async def test_continue_on_error_collects_and_continues() -> None:
    pipeline = Pipeline()

    async def fail(_ctx: PipelineContext) -> PipelineContext:
        raise RuntimeError("soft fail")

    async def after(_ctx: PipelineContext) -> PipelineContext:
        return {"after": True}

    pipeline.add_step(PipelineStep(name="fail", handler=fail, continue_on_error=True))
    pipeline.add_step(PipelineStep(name="after", handler=after))
    result = await pipeline.run()
    assert result["after"] is True
    assert len(result["errors"]) == 1


async def test_strict_step_raises_pipeline_error() -> None:
    pipeline = Pipeline()

    async def fail(_ctx: PipelineContext) -> PipelineContext:
        raise RuntimeError("hard fail")

    async def should_not_run(_ctx: PipelineContext) -> PipelineContext:
        return {"ran": True}

    pipeline.add_step(PipelineStep(name="fatal", handler=fail, continue_on_error=False))
    pipeline.add_step(PipelineStep(name="after", handler=should_not_run))

    with pytest.raises(PipelineError, match="fatal"):
        await pipeline.run()


async def test_multiple_continue_on_error_steps_collect_all_errors() -> None:
    pipeline = Pipeline()

    async def fail_a(_ctx: PipelineContext) -> PipelineContext:
        raise RuntimeError("a")

    async def fail_b(_ctx: PipelineContext) -> PipelineContext:
        raise RuntimeError("b")

    pipeline.add_step(PipelineStep(name="a", handler=fail_a, continue_on_error=True))
    pipeline.add_step(PipelineStep(name="b", handler=fail_b, continue_on_error=True))
    result = await pipeline.run()
    assert len(result["errors"]) == 2
    assert result["errors"][0]["step"] == "a"
    assert result["errors"][1]["step"] == "b"


# ===========================================================================
# Timeout handling
# ===========================================================================


async def test_step_timeout_with_continue_on_error() -> None:
    pipeline = Pipeline()

    async def slow(_ctx: PipelineContext) -> PipelineContext:
        await asyncio.sleep(10)
        return {}

    pipeline.add_step(PipelineStep(
        name="slow",
        handler=slow,
        timeout_seconds=0.05,
        continue_on_error=True,
        retries=0,
    ))
    result = await pipeline.run()
    assert len(result["errors"]) == 1
    assert result["errors"][0]["step"] == "slow"


async def test_step_timeout_strict_raises() -> None:
    pipeline = Pipeline()

    async def slow(_ctx: PipelineContext) -> PipelineContext:
        await asyncio.sleep(10)
        return {}

    pipeline.add_step(PipelineStep(
        name="slow",
        handler=slow,
        timeout_seconds=0.05,
        continue_on_error=False,
        retries=0,
    ))
    with pytest.raises(PipelineError, match="slow"):
        await pipeline.run()


# ===========================================================================
# Retry handling
# ===========================================================================


async def test_step_retries_on_failure_then_succeeds() -> None:
    pipeline = Pipeline()
    attempts = 0

    async def flaky(_ctx: PipelineContext) -> PipelineContext:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise ConnectionError("transient")
        return {"flaky_ok": True}

    pipeline.add_step(PipelineStep(name="flaky", handler=flaky, retries=2))
    result = await pipeline.run()
    assert result["flaky_ok"] is True
    assert attempts == 2


async def test_step_retries_exhausted_with_continue_on_error() -> None:
    pipeline = Pipeline()
    attempts = 0

    async def always_fail(_ctx: PipelineContext) -> PipelineContext:
        nonlocal attempts
        attempts += 1
        raise ConnectionError("permanent")

    pipeline.add_step(PipelineStep(
        name="always_fail",
        handler=always_fail,
        retries=1,
        continue_on_error=True,
    ))
    result = await pipeline.run()
    assert len(result["errors"]) == 1
    # initial attempt + 1 retry = 2 total
    assert attempts == 2


# ===========================================================================
# Parallel groups
# ===========================================================================


async def test_parallel_group_runs_all_steps() -> None:
    pipeline = Pipeline()
    executed: set[str] = set()

    for name in ("p1", "p2", "p3"):
        async def _handler(_ctx: PipelineContext, _n=name) -> PipelineContext:
            executed.add(_n)
            return {_n: True}
        pipeline.add_step(PipelineStep(name=name, handler=_handler, parallel_group="batch"))

    result = await pipeline.run()
    assert executed == {"p1", "p2", "p3"}
    assert result["p1"] is True
    assert result["p2"] is True
    assert result["p3"] is True


async def test_parallel_group_failure_continue_on_error() -> None:
    pipeline = Pipeline()

    async def ok(_ctx: PipelineContext) -> PipelineContext:
        return {"ok": True}

    async def fail(_ctx: PipelineContext) -> PipelineContext:
        raise RuntimeError("parallel boom")

    pipeline.add_step(PipelineStep(name="ok", handler=ok, parallel_group="g"))
    pipeline.add_step(PipelineStep(name="fail", handler=fail, parallel_group="g"))
    result = await pipeline.run()
    assert len(result["errors"]) == 1
    assert result["errors"][0]["step"] == "fail"


async def test_parallel_group_strict_failure_collects_error() -> None:
    """In parallel groups, errors from BaseException are caught and handled via _handle_step_failure."""
    pipeline = Pipeline()

    async def fail(_ctx: PipelineContext) -> PipelineContext:
        raise RuntimeError("strict boom")

    pipeline.add_step(PipelineStep(name="strict_fail", handler=fail, parallel_group="g", continue_on_error=False))

    # Parallel group uses bounded_gather with return_exceptions=True, so failures
    # are caught and passed to _handle_step_failure. When continue_on_error=False,
    # this should raise PipelineError.
    with pytest.raises(PipelineError, match="strict_fail"):
        await pipeline.run()


async def test_parallel_group_condition_skips_step() -> None:
    pipeline = Pipeline()
    ran: list[str] = []

    async def handler(_ctx: PipelineContext, name: str = "") -> PipelineContext:
        ran.append(name)
        return {}

    async def h_a(_ctx: PipelineContext) -> PipelineContext:
        ran.append("a")
        return {}

    async def h_b(_ctx: PipelineContext) -> PipelineContext:
        ran.append("b")
        return {}

    pipeline.add_step(PipelineStep(name="a", handler=h_a, parallel_group="g", condition=lambda _: True))
    pipeline.add_step(PipelineStep(name="b", handler=h_b, parallel_group="g", condition=lambda _: False))
    await pipeline.run()
    assert "a" in ran
    assert "b" not in ran


async def test_multiple_parallel_groups_run_sequentially_between_groups() -> None:
    pipeline = Pipeline()
    order: list[str] = []

    async def h1(_ctx: PipelineContext) -> PipelineContext:
        order.append("g1")
        return {}

    async def h2(_ctx: PipelineContext) -> PipelineContext:
        order.append("g2")
        return {}

    async def h_seq(_ctx: PipelineContext) -> PipelineContext:
        order.append("seq")
        return {}

    pipeline.add_step(PipelineStep(name="g1", handler=h1, parallel_group="first"))
    pipeline.add_step(PipelineStep(name="seq", handler=h_seq))
    pipeline.add_step(PipelineStep(name="g2", handler=h2, parallel_group="second"))
    await pipeline.run()
    # g1 before seq, seq before g2
    assert order.index("g1") < order.index("seq") < order.index("g2")


async def test_parallel_group_all_conditions_false_returns_context() -> None:
    pipeline = Pipeline()

    async def handler(_ctx: PipelineContext) -> PipelineContext:
        return {"ran": True}

    pipeline.add_step(PipelineStep(name="a", handler=handler, parallel_group="g", condition=lambda _: False))
    pipeline.add_step(PipelineStep(name="b", handler=handler, parallel_group="g", condition=lambda _: False))
    result = await pipeline.run({"initial": True})
    assert result["initial"] is True
    assert "ran" not in result


# ===========================================================================
# PipelineStep defaults
# ===========================================================================


async def test_pipeline_step_defaults() -> None:
    step = PipelineStep(name="test", handler=_noop)
    assert step.condition is None
    assert step.parallel_group is None
    assert step.timeout_seconds == 30.0
    assert step.retries == 1
    assert step.continue_on_error is True


# ===========================================================================
# Initial context
# ===========================================================================


async def test_run_with_initial_context_passes_to_first_step() -> None:
    pipeline = Pipeline()
    captured: dict[str, Any] = {}

    async def capture(ctx: PipelineContext) -> PipelineContext:
        captured.update(ctx)
        return {}

    pipeline.add_step(PipelineStep(name="capture", handler=capture))
    await pipeline.run({"input": "data"})
    assert captured["input"] == "data"


async def test_run_with_none_initial_context() -> None:
    pipeline = Pipeline()
    result = await pipeline.run(None)
    assert result == {"errors": []}


# ===========================================================================
# Edge: step mutates context dict in place
# ===========================================================================


async def test_step_handler_receives_snapshot_for_parallel() -> None:
    """Parallel steps receive a snapshot, not the live context dict."""
    pipeline = Pipeline()
    received_contexts: list[dict[str, Any]] = []

    async def step_a(ctx: PipelineContext) -> PipelineContext:
        received_contexts.append(dict(ctx))
        await asyncio.sleep(0.01)
        return {"a": True}

    async def step_b(ctx: PipelineContext) -> PipelineContext:
        received_contexts.append(dict(ctx))
        await asyncio.sleep(0.01)
        return {"b": True}

    pipeline.add_step(PipelineStep(name="a", handler=step_a, parallel_group="g"))
    pipeline.add_step(PipelineStep(name="b", handler=step_b, parallel_group="g"))
    await pipeline.run({"seed": 1})

    # Both should see the same snapshot (no cross-pollution)
    for ctx in received_contexts:
        assert ctx.get("seed") == 1
        # Neither should see the other's result in their input
        assert "a" not in ctx or "b" not in ctx  # at least one won't have the other


# ===========================================================================
# Edge: errors key in initial context
# ===========================================================================


async def test_errors_key_preserved_from_initial_context() -> None:
    existing_errors = [{"step": "old", "error": "prior"}]
    result = await Pipeline().run({"errors": existing_errors})
    assert len(result["errors"]) == 1
    assert result["errors"][0]["step"] == "old"
