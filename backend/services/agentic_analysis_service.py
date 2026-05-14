"""Foundry-backed agentic reasoning layered on top of deterministic URL scanning."""

import json
import logging
import os
from typing import Any

import httpx

from services.url_analysis_service import URLAnalysisService

logger = logging.getLogger(__name__)


class AgenticAnalysisService:
    def __init__(self, url_analysis_service: URLAnalysisService):
        self._url_analysis_service = url_analysis_service
        self._endpoint = os.getenv(
            "GROVE_FOUNDRY_CHAT_URL",
            "https://grove-gateway-prod.azure-api.net/grove-foundry-prod/openai/v1/chat/completions",
        )
        self._api_key = os.getenv("GROVE_API_KEY")
        self._model = os.getenv("GROVE_FOUNDRY_MODEL", "gpt-5.4")
        self._timeout = float(os.getenv("GROVE_FOUNDRY_TIMEOUT_SECS", "20"))
        self._agent_chain = self._parse_agent_chain()
        self._agent_prompts = self._load_agent_prompts()

    async def scan_url(self, url: str, page_content: str = "") -> dict[str, Any]:
        result = await self._url_analysis_service.scan_url(url, page_content=page_content)

        if not self._api_key:
            result["agenticAnalysis"] = {
                "available": False,
                "provider": "microsoft-foundry",
                "model": self._model,
                "error": "GROVE_API_KEY is not configured.",
            }
            return result

        try:
            pipeline = result.get("urlRecord") or {}
            context = self._build_prompt_payload(url, pipeline, result)
            steps = await self._run_agent_chain(context)
            result["agenticAnalysis"] = self._normalize_agentic_result(steps, pipeline)
        except Exception as exc:
            logger.warning("Foundry agentic analysis failed: %s", exc)
            result["agenticAnalysis"] = {
                "available": False,
                "provider": "microsoft-foundry",
                "model": self._model,
                "error": str(exc),
            }

        return result

    async def _run_agent_chain(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        shared_state: dict[str, Any] = {}

        for agent_id in self._agent_chain:
            step = await self._run_agent_step(agent_id, context, steps, shared_state)
            steps.append(step)
            shared_state[agent_id] = {
                "decision": step.get("decision"),
                "confidence": step.get("confidence"),
                "scoreAdjustment": step.get("scoreAdjustment"),
            }

        return steps

    async def _run_agent_step(
        self,
        agent_id: str,
        context: dict[str, Any],
        previous_steps: list[dict[str, Any]],
        shared_state: dict[str, Any],
    ) -> dict[str, Any]:
        prompt_meta = self._agent_prompts.get(agent_id, self._build_generic_agent_prompt(agent_id))

        user_payload = {
            "agentId": agent_id,
            "role": prompt_meta.get("role", agent_id),
            "task": prompt_meta.get("task"),
            "context": context,
            "previousSteps": previous_steps,
            "sharedState": shared_state,
            "outputSchema": {
                "decision": "string",
                "confidence": "float 0-1",
                "scoreAdjustment": "integer -15..15",
                "signals": "string[]",
                "reasoning": "string[]",
                "recommendedActions": "string[]",
            },
        }

        payload = {
            "model": self._model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        f"{prompt_meta.get('system')} "
                        "Return JSON only. Be conservative. Do not invent evidence. "
                        "confidence must be 0-1 and scoreAdjustment must be an integer between -15 and 15."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(user_payload, default=str),
                },
            ],
        }

        headers = {
            "Content-Type": "application/json",
            "api-key": self._api_key,
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(self._endpoint, headers=headers, json=payload)
            response.raise_for_status()

        data = response.json()
        message = (((data.get("choices") or [{}])[0]).get("message") or {})
        content = message.get("content", "")

        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))

        parsed = self._extract_json(content)
        return {
            "agentId": agent_id,
            "role": prompt_meta.get("role", agent_id),
            "decision": str(parsed.get("decision") or "undetermined"),
            "confidence": round(max(0.0, min(1.0, float(parsed.get("confidence") or 0.0))), 2),
            "scoreAdjustment": int(max(-15, min(15, round(float(parsed.get("scoreAdjustment") or 0))))),
            "signals": self._ensure_string_list(parsed.get("signals")),
            "reasoning": self._ensure_string_list(parsed.get("reasoning")),
            "recommendedActions": self._ensure_string_list(parsed.get("recommendedActions")),
        }

    def _build_prompt_payload(self, url: str, pipeline: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        risk_breakdown = result.get("riskBreakdown") or []
        top_breakdown = sorted(
            risk_breakdown,
            key=lambda item: item.get("contribution", 0),
            reverse=True,
        )[:6]

        return {
            "url": url,
            "pipeline": {
                "riskScore": pipeline.get("riskScore"),
                "status": pipeline.get("status"),
                "threatClassification": pipeline.get("threatClassification"),
                "payloadTypes": pipeline.get("payloadTypes", []),
                "dnsStatus": pipeline.get("dnsStatus"),
                "domainAgeDays": (pipeline.get("hostingFlags") or {}).get("domainAgeDays"),
                "sslValid": (pipeline.get("hostingFlags") or {}).get("sslValid"),
                "hasIpAddress": (pipeline.get("urlStructure") or {}).get("hasIpAddress"),
                "hasSuspiciousTld": (pipeline.get("urlStructure") or {}).get("hasSuspiciousTld"),
                "entropyScore": (pipeline.get("urlStructure") or {}).get("entropyScore"),
                "dgaAnalysis": pipeline.get("dgaAnalysis"),
                "homoglyphAnalysis": pipeline.get("homoglyphAnalysis"),
                "brandImpersonation": pipeline.get("brandImpersonation"),
                "structuralAnalysis": pipeline.get("structuralAnalysis"),
            },
            "topRiskContributors": top_breakdown,
            "similarThreatCount": len(result.get("similarThreats") or []),
            "threatIntelMatchCount": len(result.get("threatIntelMatches") or []),
            "recommendedAction": result.get("recommendedAction"),
            "waterfallTier": result.get("waterfallTier"),
        }

    def _normalize_agentic_result(self, steps: list[dict[str, Any]], pipeline: dict[str, Any]) -> dict[str, Any]:
        if not steps:
            raise ValueError("No agent steps returned from Foundry chain.")

        workflow_type = "single-agent" if len(steps) == 1 else "multi-agent"

        base_score = int(round(float(pipeline.get("riskScore") or 0)))

        # Prefer final action agent adjustment, otherwise use average chain adjustment.
        final_step = steps[-1]
        action_step = next((step for step in steps if step.get("agentId") == "action"), final_step)
        if action_step:
            adjustment = int(max(-15, min(15, round(float(action_step.get("scoreAdjustment") or 0)))))
        else:
            avg_adj = sum(step.get("scoreAdjustment", 0) for step in steps) / len(steps)
            adjustment = int(max(-15, min(15, round(avg_adj))))

        adjusted_score = max(0, min(100, base_score + adjustment))
        verdict_source = next((step for step in steps if step.get("agentId") == "classifier"), final_step)

        merged_signals = self._dedupe_ordered(
            [signal for step in steps for signal in step.get("signals", [])]
        )
        merged_reasoning = self._dedupe_ordered(
            [f"[{step.get('role', step.get('agentId', 'agent'))}] {line}" for step in steps for line in step.get("reasoning", [])]
        )
        merged_actions = self._dedupe_ordered(
            [line for step in steps for line in step.get("recommendedActions", [])]
        )

        avg_confidence = sum(step.get("confidence", 0.0) for step in steps) / len(steps)
        decisions = [step.get("decision", "undetermined") for step in steps]
        decision_counts: dict[str, int] = {}
        for decision in decisions:
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
        top_decision, top_count = max(decision_counts.items(), key=lambda item: item[1])
        agreement_ratio = round(top_count / len(decisions), 2)

        summary = (
            f"{len(steps)}-agent workflow ({workflow_type}) completed. "
            f"Primary decision: {top_decision}. "
            f"Agreement: {int(agreement_ratio * 100)}%."
        )

        return {
            "available": True,
            "provider": "microsoft-foundry",
            "model": self._model,
            "workflowType": workflow_type,
            "agentChain": self._agent_chain,
            "summary": summary,
            "verdict": verdict_source.get("decision") or pipeline.get("threatClassification") or "suspicious",
            "confidence": round(max(0.0, min(1.0, avg_confidence)), 2),
            "scoreAdjustment": adjustment,
            "agenticRiskScore": adjusted_score,
            "agenticStatus": self._score_to_status(adjusted_score),
            "decisiveSignals": merged_signals,
            "reasoningSteps": merged_reasoning,
            "recommendedActions": merged_actions,
            "workflowSteps": steps,
            "agreement": {
                "topDecision": top_decision,
                "ratio": agreement_ratio,
                "counts": decision_counts,
            },
        }

    def _parse_agent_chain(self) -> list[str]:
        configured = os.getenv("AGENTIC_AGENT_CHAIN", "classifier")
        chain = [item.strip() for item in configured.split(",") if item.strip()]
        return chain or ["classifier"]

    def _load_agent_prompts(self) -> dict[str, dict[str, str]]:
        defaults = {
            "triage": {
                "role": "triage-agent",
                "task": "Prioritize the strongest supporting and contradicting signals from deterministic pipeline evidence.",
                "system": (
                    "You are Triage Agent. Focus only on evidence quality and signal ordering. "
                    "Do not overfit to one indicator."
                ),
            },
            "classifier": {
                "role": "classification-agent",
                "task": "Produce threat decision label using triage output and evidence context.",
                "system": (
                    "You are Classification Agent. Decide likely threat class (phishing/malware/c2/suspicious/benign) "
                    "based on evidence and prior agent outputs."
                ),
            },
            "action": {
                "role": "action-agent",
                "task": "Recommend final analyst action and bounded score adjustment respecting conservative policy.",
                "system": (
                    "You are Action Agent. Recommend block/review/allow actions and bounded score adjustment. "
                    "Be policy-safe and conservative."
                ),
            },
        }

        raw = os.getenv("AGENTIC_AGENT_PROMPTS_JSON")
        if not raw:
            return defaults

        try:
            custom = json.loads(raw)
            if not isinstance(custom, dict):
                return defaults
            for key, value in custom.items():
                if isinstance(value, dict):
                    defaults[key] = {
                        "role": str(value.get("role") or f"{key}-agent"),
                        "task": str(value.get("task") or "Analyze evidence and return structured output."),
                        "system": str(value.get("system") or "You are a security analysis agent."),
                    }
            return defaults
        except Exception:
            logger.warning("Invalid AGENTIC_AGENT_PROMPTS_JSON; falling back to defaults")
            return defaults

    def _build_generic_agent_prompt(self, agent_id: str) -> dict[str, str]:
        return {
            "role": f"{agent_id}-agent",
            "task": "Analyze provided pipeline context and previous steps, then emit structured output.",
            "system": f"You are {agent_id} agent in a multi-agent security workflow.",
        }

    def _score_to_status(self, score: int) -> str:
        if score >= 75:
            return "blocked"
        if score >= 50:
            return "under_review"
        return "allowed"

    def _ensure_string_list(self, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if item is not None]

    def _dedupe_ordered(self, items: list[str]) -> list[str]:
        seen: set[str] = set()
        output: list[str] = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            output.append(item)
        return output

    def _extract_json(self, content: str) -> dict[str, Any]:
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start == -1 or end == -1 or end <= start:
                raise ValueError("Foundry response was not valid JSON.")
            return json.loads(content[start:end + 1])