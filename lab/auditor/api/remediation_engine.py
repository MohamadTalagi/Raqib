"""AI-Assisted Remediation (IoTGuard Stage 07): turns one already-determined
compliance finding (a failing SA-IOT verdict or a failing/partial NCA
assessment) into a structured remediation blueprint via Google Gemini's
free tier.

Pure and unit-testable without a real network call, matching this
codebase's other scoring/generation engines (risk_engine.py,
policy_engine.py) - callers (remediation_routes.py) assemble the `finding`
dict from the real verdict/assessment/control rows; nothing here touches
the database.

"AI-assisted, not AI-decided" at its strongest here: the finding itself
(that a control failed, and why) is already decided by deterministic code
before this module ever runs. The prompt explicitly forbids inventing
additional vulnerabilities, CVEs, or facts beyond what's given - the model
may only explain and expand on an already-determined finding, never assert
a new one. That said, this is a prompt instruction, not a hard technical
guarantee, which is exactly why every generated blueprint carries a
human-review gate (see remediation_routes.py) before it's ever treated as
authoritative.

Uses plain httpx.post against Gemini's REST endpoint - no SDK - the same
"plain HTTP call" convention scan_scripts/cisa_kev.py already established
for an external API in this codebase. Structured output
(responseMimeType + responseSchema) keeps the response shape fixed even
though content varies call to call.
"""
import json
import os

import httpx

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GEMINI_TIMEOUT_SECONDS = 30

VALID_PRIORITIES = ("immediate", "short_term", "long_term")

RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "root_cause": {"type": "STRING"},
        "remediation_steps": {"type": "ARRAY", "items": {"type": "STRING"}},
        "priority": {"type": "STRING", "enum": list(VALID_PRIORITIES)},
        "estimated_effort": {"type": "STRING"},
        "caveats": {"type": "STRING"},
    },
    "required": ["root_cause", "remediation_steps", "priority", "estimated_effort", "caveats"],
}

PROMPT_TEMPLATE = """You are assisting a security auditor with remediation guidance for an \
IoT device compliance finding. The finding below has ALREADY been determined by \
deterministic scanning and policy evaluation - it is a fact, not something for you to \
question, second-guess, or restate as uncertain. Do not invent additional \
vulnerabilities, CVEs, or facts beyond what is given below.

Your only job: explain the likely root cause in plain language, then give concrete, \
actionable remediation steps an engineer could actually follow for this specific \
device and control, plus a rough priority and effort estimate.

FINDING
Control: {control_id} - {control_title}
Requirement: {requirement_text}
Status: {status}
Severity: {severity}
Why it failed: {reason_or_finding}
Device: {device_label}
Existing remediation note (if any): {existing_remediation}

Respond using only the fields in the provided schema."""


def build_prompt(finding: dict) -> dict:
    """finding is the normalized dict remediation_routes.py assembles from a
    real verdict or NCA assessment row - see its own docstring for the
    exact shape."""
    device_label = finding.get("device_label") or "organization-wide (no single device)"
    text = PROMPT_TEMPLATE.format(
        control_id=finding["control_id"],
        control_title=finding.get("control_title") or finding["control_id"],
        requirement_text=finding.get("requirement_text") or "(not available)",
        status=finding["status"],
        severity=finding["severity"],
        reason_or_finding=finding.get("reason_or_finding") or "(not available)",
        device_label=device_label,
        existing_remediation=finding.get("existing_remediation") or "(none recorded)",
    )
    return {
        "contents": [{"parts": [{"text": text}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": RESPONSE_SCHEMA,
        },
    }


def _parse_response(data: dict) -> dict | None:
    try:
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        parsed = json.loads(text)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        return None

    required_fields = {"root_cause", "remediation_steps", "priority", "estimated_effort", "caveats"}
    if not isinstance(parsed, dict) or not required_fields.issubset(parsed.keys()):
        return None
    if parsed["priority"] not in VALID_PRIORITIES:
        return None
    if not isinstance(parsed["remediation_steps"], list) or not all(
        isinstance(step, str) for step in parsed["remediation_steps"]
    ):
        return None
    return parsed


def call_gemini(prompt_body: dict) -> dict | None:
    """Never raises - a missing key, a rate limit, a network failure, or a
    malformed/incomplete response all return None so the caller reports an
    honest "could not generate" result rather than fabricating one, the
    same convention cisa_kev.fetch_and_cache_kev_feed() already uses for a
    failed external call."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
    url = GEMINI_API_URL.format(model=model)

    try:
        response = httpx.post(url, params={"key": api_key}, json=prompt_body, timeout=GEMINI_TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError):
        return None

    return _parse_response(data)


def generate_remediation_blueprint(finding: dict) -> dict | None:
    """The one entry point remediation_routes.py calls. Returns the parsed
    {root_cause, remediation_steps, priority, estimated_effort, caveats}
    dict, or None if generation failed for any reason."""
    return call_gemini(build_prompt(finding))
