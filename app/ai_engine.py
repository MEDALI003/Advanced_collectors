from __future__ import annotations

import json
import os
from typing import Any

import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://192.168.153.1:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama1:8b")


def build_ai_context(payload: Any, rule_alerts: list[str]) -> dict:
    return {
        "agent": payload.agent.model_dump(),
        "metrics": payload.metrics.model_dump(),
        "rule_alerts": rule_alerts,
        "logs": [x.model_dump() for x in payload.logs[:30]],
        "services": [x.model_dump() for x in payload.services[:30]],
        "file_events": [x.model_dump() for x in payload.file_events[:50]],
        "network_connections": [x.model_dump() for x in payload.network_connections[:30]],
        "top_processes": [x.model_dump() for x in payload.top_processes[:15]],
    }


def analyze_with_ai(payload: Any, rule_alerts: list[str]) -> dict:
    context = build_ai_context(payload, rule_alerts)

    prompt = f"""
You are CyberScope AI, a Healthcare SOC Analyst.

Analyze this SIEM payload and decide if it is benign, suspicious, or malicious.

Return ONLY valid JSON:

{{
  "verdict": "benign | suspicious | malicious | not_enough_evidence",
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "risk_score": 0,
  "confidence": 0.0,
  "summary": "",
  "healthcare_impact": "",
  "attack_type": "",
  "mitre_attack": [],
  "iocs": {{
    "ips": [],
    "files": [],
    "users": []
  }},
  "evidence": [],
  "recommended_actions": [],
  "false_positive_notes": ""
}}

SIEM DATA:
{json.dumps(context, default=str)}
"""

    try:
        res = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=90,
        )
        res.raise_for_status()
        raw = res.json().get("response", "").strip()

        if raw.startswith("```"):
            raw = raw.replace("```json", "").replace("```", "").strip()

        return json.loads(raw)

    except Exception as exc:
        return {
            "verdict": "not_enough_evidence",
            "risk_level": "LOW",
            "risk_score": 0,
            "confidence": 0.0,
            "summary": "AI analysis failed or returned invalid JSON.",
            "healthcare_impact": "No healthcare impact determined.",
            "attack_type": "unknown",
            "mitre_attack": [],
            "iocs": {"ips": [], "files": [], "users": []},
            "evidence": [],
            "recommended_actions": ["Check Ollama connectivity and manager logs."],
            "false_positive_notes": str(exc),
            "ai_error": True,
        }