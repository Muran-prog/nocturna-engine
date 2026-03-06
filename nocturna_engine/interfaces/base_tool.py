"""Abstract base interface for any tool plugin."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


class BaseTool(ABC):
    """Base class for all future pentest tool wrappers.

    Every plugin must implement `execute` and `parse_output`. The plugin manager
    auto-registers subclasses in a registry and controls lifecycle hooks.

    Attributes:
        name: Unique plugin name used in the registry.
        version: Wrapper version string.
        timeout_seconds: Default execution timeout.
        max_retries: Default retry count for transient failures.
        retry_exceptions: Additional exception types eligible for retry beyond defaults.
        isolated: If True, execute in a separate process for crash isolation.
    """

    name: ClassVar[str] = ""
    version: ClassVar[str] = "0.1.0"
    timeout_seconds: ClassVar[float] = 60.0
    max_retries: ClassVar[int] = 2
    isolated: ClassVar[bool] = False
    retry_exceptions: ClassVar[tuple[type[BaseException], ...]] = ()

    def __init__(self, logger: BoundLogger | None = None) -> None:
        """Initialize plugin instance.

        Args:
            logger: Optional structured logger.
        """

        self._logger: BoundLogger = logger or structlog.get_logger(self.__class__.__name__)
        self._is_initialized: bool = False

    @property
    def logger(self) -> BoundLogger:
        """Return plugin-scoped logger.

        Returns:
            BoundLogger: Structured logger.
        """

        return self._logger.bind(tool=self.name or self.__class__.__name__.lower())

    async def __aenter__(self) -> "BaseTool":
        """Enter async context and call setup hook.

        Returns:
            BaseTool: Initialized plugin instance.
        """

        await self.setup()
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: Any) -> None:
        """Exit async context and call teardown hook.

        Args:
            exc_type: Exception type if raised inside context.
            exc: Exception instance if raised inside context.
            tb: Traceback object.
        """

        await self.teardown()

    async def setup(self) -> None:
        """Initialize plugin resources.

        Subclasses may override this method to open network clients, temp files,
        or caches required for execution.
        """

        self._is_initialized = True

    async def teardown(self) -> None:
        """Release plugin resources."""

        self._is_initialized = False

    def supports_target(self, target: Target) -> bool:
        """Check whether plugin can handle a given target.

        Args:
            target: Validated target model.

        Returns:
            bool: True if plugin supports this target.
        """

        _ = target
        return True

    @abstractmethod
    async def execute(self, request: ScanRequest) -> ScanResult:
        """Run tool logic and return a normalized scan result.

        Args:
            request: Validated scan request.

        Returns:
            ScanResult: Raw plugin result.
        """

    @abstractmethod
    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        """Parse raw plugin output into normalized findings.

        Args:
            raw_output: Result payload from the tool.
            request: Original scan request.

        Returns:
            list[Finding]: Normalized findings.
        """

