"""Capability-aware planner ranking helpers."""

from __future__ import annotations

import os
import re
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from ..health import PluginHealthStatus
from ..policy import PluginPolicy, PluginPolicyEngine
from .models import AIPlan, PlanStep

_WINDOWS_DRIVE_PATTERN = re.compile(r"^[a-zA-Z]:[\\/]")
_WINDOWS_UNC_PATTERN = re.compile(r"^\\\\[^\\/]+[\\/][^\\/]+")
_DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class CapabilityAwarePlanner:
    """Ranks plugins by intent, target compatibility, health, and policy."""

    def __init__(self, policy_engine: PluginPolicyEngine) -> None:
        self._policy_engine = policy_engine

    def plan(
        self,
        *,
        target: str,
        goal: str,
        mode: str,
        plugin_descriptions: dict[str, dict[str, Any]],
        health_status: dict[str, PluginHealthStatus] | None = None,
        policy: PluginPolicy | None = None,
        max_steps: int | None = None,
    ) -> AIPlan:
        goal_tokens = self._tokenize(goal)
        inferred_target_type = self._infer_target_type(target)
        effective_policy = policy or self._policy_engine.build_policy()
        statuses = health_status or {}

        scored_steps: list[PlanStep] = []
        skipped: dict[str, str] = {}
        for name, descriptor in sorted(plugin_descriptions.items()):
            manifest = descriptor
            policy_decision = self._policy_engine.evaluate_manifest_payload(manifest, effective_policy)
            if not policy_decision.allowed:
                skipped[name] = policy_decision.reason or "policy_denied"
                continue

            health = statuses.get(name)
            if health is not None and not health.healthy:
                skipped[name] = health.reason or "health_check_failed"
                continue

            score, reasons, estimated_cost = self._score_plugin(
                plugin_name=name,
                manifest=manifest,
                goal_tokens=goal_tokens,
                inferred_target_type=inferred_target_type,
            )
            if score <= 0:
                skipped[name] = "insufficient_relevance"
                continue

            scored_steps.append(
                PlanStep(
                    tool_name=name,
                    score=score,
                    reasons=reasons,
                    fallback_tools=[],
                    estimated_cost=estimated_cost,
                )
            )

        scored_steps.sort(key=lambda item: (-item.score, item.estimated_cost, item.tool_name))
        if max_steps is not None and max_steps > 0:
            scored_steps = scored_steps[:max_steps]

        for step in scored_steps:
            step.fallback_tools = self._fallbacks_for(step, scored_steps)

        return AIPlan(
            target=target,
            goal=goal,
            mode=mode,
            steps=scored_steps,
            skipped=skipped,
        )

    @staticmethod
    def _tokenize(value: str) -> set[str]:
        separators = ["+", ",", ";", " "]
        normalized = value.lower()
        for separator in separators:
            normalized = normalized.replace(separator, " ")
        return {token.strip() for token in normalized.split() if token.strip()}

    @staticmethod
    def _infer_target_type(target: str) -> str:
        text = target.strip().strip("\"'")
        if not text:
            return "domain"

        parsed = urlparse(text)
        if parsed.scheme and parsed.netloc:
            return "url"

        if "/" in text:
            host_part = text.split("/", 1)[0].lower()
            if _DOMAIN_PATTERN.fullmatch(host_part):
                return "url"

        try:
            if "/" in text:
                ip_network(text, strict=False)
                return "cidr"
        except ValueError:
            pass

        candidate = text
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        try:
            ip_address(candidate)
            return "ip"
        except ValueError:
            pass

        inferred_path_type = CapabilityAwarePlanner._infer_path_target_type(text)
        if inferred_path_type is not None:
            return inferred_path_type

        return "domain"

    @staticmethod
    def _infer_path_target_type(target: str) -> str | None:
        expanded = os.path.expanduser(target)
        path = Path(expanded)
        try:
            if path.exists():
                if path.is_dir():
                    return "directory"
                if path.is_file():
                    return "file"
        except OSError:
            pass

        if _WINDOWS_DRIVE_PATTERN.match(target) or _WINDOWS_UNC_PATTERN.match(target):
            return "directory" if CapabilityAwarePlanner._looks_like_directory_path(target) else "file"

        if "\\" in target and "://" not in target:
            return "directory" if CapabilityAwarePlanner._looks_like_directory_path(target) else "file"

        if target.startswith(("./", "../", "/", "~")):
            return "directory" if CapabilityAwarePlanner._looks_like_directory_path(target) else "file"

        if "/" in target and "://" not in target:
            return "directory" if CapabilityAwarePlanner._looks_like_directory_path(target) else "file"

        return None

    @staticmethod
    def _looks_like_directory_path(target: str) -> bool:
        normalized = target.replace("\\", "/")
        if normalized.endswith("/"):
            return True
        leaf = normalized.rsplit("/", 1)[-1]
        if leaf in {"", ".", ".."}:
            return True
        return "." not in leaf

    def _score_plugin(
        self,
        *,
        plugin_name: str,
        manifest: dict[str, Any],
        goal_tokens: set[str],
        inferred_target_type: str,
    ) -> tuple[float, list[str], float]:
        score = 0.0
        reasons: list[str] = []
        capabilities = manifest.get("capabilities", [])
        supported_targets = set(manifest.get("supported_targets", []))
        supported_phases = set(manifest.get("supported_phases", []))

        matching_targets = sorted(self._target_match_candidates(inferred_target_type).intersection(supported_targets))
        if matching_targets:
            score += 2.0
            reasons.append(f"supports target type '{matching_targets[0]}'")
        elif supported_targets:
            reasons.append("target type mismatch")
            score -= 1.0

        cap_tokens = set(self._capability_tokens(capabilities))
        phase_tokens = {item.lower() for item in supported_phases}
        overlap = sorted(goal_tokens.intersection(cap_tokens.union(phase_tokens)))
        if overlap:
            score += float(len(overlap))
            reasons.append(f"goal overlap: {', '.join(overlap)}")

        estimated_cost = 1.0
        if capabilities:
            cost_values = [float(item.get("cost_hint", 1.0)) for item in capabilities if isinstance(item, dict)]
            if cost_values:
                estimated_cost = sum(cost_values) / len(cost_values)
                score += max(0.1, 1.5 - estimated_cost)
                reasons.append(f"estimated cost {estimated_cost:.2f}")

        if not reasons:
            reasons.append("default ranking")
            score += 0.1

        if "full" in goal_tokens or "max_external_pentest" in goal_tokens:
            if plugin_name in {"nmap", "nuclei", "ffuf", "subfinder", "dns_resolver"}:
                score += 1.0
                reasons.append("priority for broad external coverage")

        return score, reasons, estimated_cost

    @staticmethod
    def _target_match_candidates(target_type: str) -> set[str]:
        aliases: dict[str, set[str]] = {
            "domain": {"domain", "fqdn", "host", "url"},
            "url": {"url", "domain", "web"},
            "ip": {"ip", "host", "network"},
            "cidr": {"cidr", "ip", "network", "subnet"},
            "directory": {"directory", "source_code", "filesystem", "path"},
            "file": {"file", "directory", "source_code", "filesystem", "path"},
        }
        candidates = set(aliases.get(target_type, set()))
        candidates.add(target_type)
        return candidates

    @staticmethod
    def _capability_tokens(capabilities: Iterable[Any]) -> set[str]:
        tokens: set[str] = set()
        for item in capabilities:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip().lower()
                category = str(item.get("category", "")).strip().lower()
                tags = [str(tag).strip().lower() for tag in item.get("tags", [])]
                if name:
                    tokens.add(name)
                if category:
                    tokens.add(category)
                tokens.update(tag for tag in tags if tag)
            elif isinstance(item, str):
                tokens.add(item.strip().lower())
        return tokens

    @staticmethod
    def _fallbacks_for(current: PlanStep, ranked_steps: list[PlanStep]) -> list[str]:
        fallbacks = [
            step.tool_name
            for step in ranked_steps
            if step.tool_name != current.tool_name and step.score >= max(0.5, current.score - 1.5)
        ]
        return fallbacks[:3]
