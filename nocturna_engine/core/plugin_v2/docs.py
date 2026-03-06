"""Documentation helpers for plugin author experience."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .contracts import PluginManifest


def generate_plugin_docs(
    manifest: PluginManifest,
    *,
    options_model: type[BaseModel] | None = None,
) -> dict[str, Any]:
    """Generate human and machine docs from manifest and options model."""

    schema = manifest.option_schema
    if options_model is not None:
        schema = options_model.model_json_schema()

    capability_lines = [
        f"- `{item.name}` ({item.category}) coverage={item.coverage_hint:.2f} cost={item.cost_hint:.2f}"
        for item in manifest.capabilities
    ]
    human_doc = "\n".join(
        [
            f"# {manifest.display_name}",
            "",
            f"- Plugin ID: `{manifest.id}`",
            f"- Version: `{manifest.version}`",
            f"- Supported targets: {', '.join(manifest.supported_targets) or 'any'}",
            f"- Supported phases: {', '.join(manifest.supported_phases) or 'any'}",
            "- Capabilities:",
            *(capability_lines or ["- none"]),
        ]
    )
    return {
        "manifest": manifest.machine_readable(include_schema=False),
        "option_schema": schema,
        "human_markdown": human_doc,
    }

