"""Normalization pipeline: detect format, parse, validate, deduplicate."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from time import perf_counter

from nocturna_engine.normalization.errors import NormalizationError
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import ParseIssue
from nocturna_engine.normalization.pipeline.config import NormalizationConfig
from nocturna_engine.normalization.pipeline.result import NormalizationResult
from nocturna_engine.normalization.pipeline.runner._helpers import (
    build_parser,
    detect,
    finalize,
    lookup_parser,
    make_error_result,
)
from nocturna_engine.normalization.registry import ParserRegistry, get_global_registry


class NormalizationPipeline:
    """Orchestrates format detection, parsing, validation, and deduplication.

    Usage::

        pipeline = NormalizationPipeline()
        result = await pipeline.normalize(raw_data, config=config)
        for finding in result.findings:
            print(finding.title, finding.severity)
    """

    def __init__(
        self,
        *,
        registry: ParserRegistry | None = None,
    ) -> None:
        """Initialize pipeline with an optional custom parser registry.

        Args:
            registry: Parser registry. Uses global registry if not provided.
        """
        self._registry = registry or get_global_registry()

    async def normalize(
        self,
        data: bytes | str,
        *,
        config: NormalizationConfig,
    ) -> NormalizationResult:
        """Run the full normalization pipeline on complete input data.

        Steps:
        1. Detect input format
        2. Look up and instantiate parser
        3. Parse data into findings
        4. Validate findings
        5. Deduplicate by fingerprint
        6. Check error thresholds

        Args:
            data: Complete raw output from a security tool.
            config: Normalization configuration.

        Returns:
            NormalizationResult: Pipeline result with findings and metadata.
        """
        start_time = perf_counter()

        # Step 1: Detect format.
        detection, err = detect(data, config, start_time)
        if err is not None:
            return err

        # Step 2: Look up parser.
        parser_class, err = lookup_parser(detection, config, self._registry, start_time)
        if err is not None:
            return err

        # Step 3: Instantiate and run parser.
        parser = build_parser(parser_class, config)  # type: ignore[arg-type]

        try:
            parse_result = await parser.parse(data)
        except NormalizationError as exc:
            return make_error_result(
                exc, start_time, detection=detection, parser_name=parser.parser_name,
            )
        except Exception as exc:
            logging.getLogger("normalization.pipeline").warning(
                "Unexpected error during parse: %s", exc, exc_info=True,
            )
            return make_error_result(
                exc, start_time, detection=detection, parser_name=parser.parser_name,
            )

        # Steps 4-6: Deduplicate, check thresholds, build result.
        return finalize(parse_result, detection, parser.parser_name, config, start_time)

    async def normalize_stream(
        self,
        stream: AsyncIterator[bytes],
        *,
        config: NormalizationConfig,
        sniff_bytes: bytes | None = None,
    ) -> NormalizationResult:
        """Run the normalization pipeline on a streaming input.

        Args:
            stream: Async byte chunk iterator.
            config: Normalization configuration.
            sniff_bytes: Optional pre-read bytes for format detection.
                If not provided, the first chunk from the stream is used.

        Returns:
            NormalizationResult: Pipeline result with findings and metadata.
        """
        start_time = perf_counter()

        # Read first chunk for format detection if not provided.
        first_chunk: bytes | None = sniff_bytes
        if first_chunk is None:
            try:
                first_chunk = await stream.__anext__()
            except StopAsyncIteration:
                return NormalizationResult(
                    issues=[ParseIssue(message="Empty stream.")],
                    stats=NormalizationStats(
                        duration_seconds=perf_counter() - start_time,
                    ),
                    aborted=True,
                    abort_reason="Empty stream.",
                )

        try:
            # Detect format from first chunk.
            detection, err = detect(first_chunk, config, start_time)
            if err is not None:
                return err

            # Look up parser.
            parser_class, err = lookup_parser(detection, config, self._registry, start_time)
            if err is not None:
                return err

            # Create combined stream: first_chunk + remaining stream.
            async def _combined_stream() -> AsyncIterator[bytes]:
                yield first_chunk  # type: ignore[misc]
                async for chunk in stream:
                    yield chunk

            parser = build_parser(parser_class, config)  # type: ignore[arg-type]

            try:
                parse_result = await parser.parse_stream(_combined_stream())
            except NormalizationError as exc:
                return make_error_result(
                    exc, start_time, detection=detection, parser_name=parser.parser_name,
                )
            except Exception as exc:
                logging.getLogger("normalization.pipeline").warning(
                    "Unexpected error during parse_stream: %s", exc, exc_info=True,
                )
                return make_error_result(
                    exc, start_time, detection=detection, parser_name=parser.parser_name,
                )

            # Deduplicate, check thresholds, build result.
            return finalize(parse_result, detection, parser.parser_name, config, start_time)
        finally:
            # Ensure the stream is closed to avoid resource leaks.
            aclose = getattr(stream, "aclose", None)
            if aclose is not None:
                await aclose()
