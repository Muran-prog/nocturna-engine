"""Process-level isolation runner for plugin execution.

Uses ``multiprocessing`` with the ``spawn`` start method to run tool.execute()
in a separate process.  This protects the engine from plugins that segfault,
OOM, or enter infinite loops.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import multiprocessing.queues
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult

if TYPE_CHECKING:
    from nocturna_engine.interfaces.base_tool import BaseTool

logger = structlog.get_logger("isolation_runner")

# ---------------------------------------------------------------------------
# Spawn context (cross-platform safe, required on Windows)
# ---------------------------------------------------------------------------
_ctx = multiprocessing.get_context("spawn")


# ---------------------------------------------------------------------------
# Worker — top-level so it can be pickled by multiprocessing
# ---------------------------------------------------------------------------


def _worker(
    tool_module: str,
    tool_qualname: str,
    request_json: str,
    result_queue: multiprocessing.Queue,  # type: ignore[type-arg]
) -> None:
    """Execute the tool in a child process and put the result JSON on *result_queue*.

    This function is deliberately a module-level function (not a closure) so that
    the ``spawn`` start method can serialise it.

    Args:
        tool_module: Fully-qualified module path of the tool class.
        tool_qualname: Qualified class name within the module.
        request_json: JSON-serialised :class:`ScanRequest`.
        result_queue: Multiprocessing queue for returning the result JSON.
    """
    import asyncio as _asyncio
    import importlib

    try:
        mod = importlib.import_module(tool_module)
        # Support nested classes via qualname (e.g. "Outer.Inner")
        tool_cls = mod
        for attr in tool_qualname.split("."):
            tool_cls = getattr(tool_cls, attr)

        tool_instance: BaseTool = tool_cls()  # type: ignore[operator]
        request = ScanRequest.model_validate_json(request_json)
        result = _asyncio.run(tool_instance.execute(request))
        result_queue.put(result.model_dump_json())
    except Exception as exc:  # noqa: BLE001
        # Build a minimal failure result so the parent always gets valid JSON.
        fail = ScanResult(
            request_id="unknown",
            tool_name=tool_qualname,
            success=False,
            error_message=f"Isolated worker crashed: {exc!r}",
        )
        try:
            result_queue.put(fail.model_dump_json())
        except Exception:  # noqa: BLE001
            pass  # Nothing we can do — parent will handle the timeout/missing result.


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def execute_tool_isolated(
    tool_class: type[BaseTool],
    request: ScanRequest,
    timeout_seconds: float,
) -> ScanResult:
    """Run *tool_class*.execute(*request*) in an isolated child process.

    Args:
        tool_class: The **class** (not instance) of the tool to execute.
        request: Scan request to pass to the tool.
        timeout_seconds: Maximum wall-clock time.  If exceeded the child
            process is killed and a failure :class:`ScanResult` is returned.

    Returns:
        ScanResult: Either the tool's real result or a synthetic failure.
    """
    started_at = datetime.now(UTC)

    tool_module = tool_class.__module__
    tool_qualname = tool_class.__qualname__
    request_json = request.model_dump_json()

    result_queue: multiprocessing.Queue = _ctx.Queue()  # type: ignore[type-arg]
    process = _ctx.Process(
        target=_worker,
        args=(tool_module, tool_qualname, request_json, result_queue),
        daemon=True,
    )

    def _run_and_join() -> str | None:
        """Start the process, wait up to *timeout_seconds*, and return the result JSON."""
        process.start()
        process.join(timeout=timeout_seconds)

        if process.is_alive():
            process.kill()
            process.join(timeout=5)
            return None

        if process.exitcode != 0:
            # Process crashed (segfault, OOM, etc.)
            try:
                if not result_queue.empty():
                    return result_queue.get_nowait()
            except Exception:  # noqa: BLE001
                pass
            return None

        try:
            return result_queue.get_nowait()
        except Exception:  # noqa: BLE001
            return None

    loop = asyncio.get_running_loop()
    result_json = await loop.run_in_executor(None, _run_and_join)

    if result_json is not None:
        try:
            result = ScanResult.model_validate_json(result_json)
            result.request_id = request.request_id
            result.tool_name = getattr(tool_class, "name", tool_qualname)
            return result
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "isolated_result_deserialization_failed",
                tool=tool_qualname,
                error=str(exc),
            )

    # Timeout or crash — build a failure result.
    finished_at = datetime.now(UTC)
    duration_ms = int((finished_at - started_at).total_seconds() * 1000)

    exit_code = getattr(process, "exitcode", None)
    if process.is_alive() or exit_code is None:
        reason = "Isolated tool execution timed out"
    else:
        reason = f"Isolated tool process exited with code {exit_code}"

    return ScanResult(
        request_id=request.request_id,
        tool_name=getattr(tool_class, "name", tool_qualname),
        success=False,
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        error_message=reason,
        metadata={"isolated": True, "exit_code": exit_code},
    )
