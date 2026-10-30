"""Contextual review by a Nemotron model behind an OpenAI-compatible endpoint.

Privacy contract
* Runs only with explicit consent and a configured endpoint.
* Receives masked text only: every deterministic finding is already `[CATEGORY]`.
* One bounded request per audit (input and output limits, timeout).
* The model can annotate findings and add located concerns; it can never remove a finding
  or mark a document safe.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from .config import AIConfig
from .models import AIOutcome, Context, Finding, Rule

Transport = Callable[[str, str, Optional[Dict[str, Any]], Dict[str, str], float], Dict[str, Any]]

RELEVANCE = {"confirmed", "likely", "unlikely"}
SEVERITIES = {"low", "medium", "high"}  # the model may never raise a CRITICAL finding
MAX_CONCERNS = 10
THINK_RE = re.compile(r"<think>[\s\S]*?</think>", re.IGNORECASE)

SYSTEM_PROMPT = (
    "You are a privacy reviewer. You receive a document excerpt in which sensitive values were already "
    "replaced by placeholders such as [EMAIL] or [API_KEY]. Judge whether the document is appropriate to share "
    "in the stated context. Reply with ONE JSON object and nothing else, using exactly this shape:\n"
    '{"summary": str, "assessments": [{"finding_id": str, "relevance": "confirmed|likely|unlikely", "rationale": str}], '
    '"additional_concerns": [{"quote": str, "reason": str, "severity": "low|medium|high"}]}\n'
    "Each quote must be copied exactly from the excerpt and must not contain a placeholder. "
    "Never state that the document is safe; you only report concerns."
)


class AIError(Exception):
    """Raised for any failure to obtain a valid model response."""


@dataclass
class AIConcern:
    quote: str
    reason: str
    severity: str


@dataclass
class AIAnalysis:
    outcome: AIOutcome
    summary: str = ""
    assessments: Dict[str, Dict[str, str]] = field(default_factory=dict)
    concerns: List[AIConcern] = field(default_factory=list)


def http_json(method: str, url: str, payload: Optional[Dict[str, Any]], headers: Dict[str, str], timeout: float) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise AIError(f"The endpoint returned HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise AIError("The endpoint could not be reached (network error or timeout).") from None
    except ValueError:
        raise AIError("The endpoint returned a response that is not valid JSON.") from None


def _headers(config: AIConfig) -> Dict[str, str]:
    return {"Authorization": f"Bearer {config.api_key}", "Content-Type": "application/json", "Accept": "application/json"}


def list_models(config: AIConfig, transport: Transport = http_json) -> List[str]:
    """Return model IDs offered by the endpoint (used by the Settings connection test)."""
    if not config.configured:
        raise AIError("AI is not configured: set AI_API_KEY in .env.")
    data = transport("GET", f"{config.base_url}/models", None, _headers(config), config.timeout_seconds)
    return sorted(str(m.get("id", "")) for m in data.get("data", []) if m.get("id"))


def build_messages(
    masked_text: str,
    findings: Sequence[Finding],
    context: Context,
    focus: str,
    rules: Sequence[Rule],
) -> List[Dict[str, str]]:
    summary = [
        {"finding_id": f.finding_id, "category": f.category.value, "severity": f.severity.name.lower(), "excerpt": f.masked_excerpt}
        for f in findings if f.located
    ]
    policies = [{"name": r.name, "description": r.description} for r in rules if r.applies_to(context)]  # no literal terms
    user = (
        f"Sharing context: {context.value}\nSpecial attention: {focus or 'general confidentiality'}\n"
        f"Workspace policies: {json.dumps(policies)}\nDeterministic findings: {json.dumps(summary)}\n"
        f"--- DOCUMENT EXCERPT (masked) ---\n{masked_text}"
    )
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]


def parse_response(raw: str, known_ids: Sequence[str], excerpt: str) -> AIAnalysis:
    """Validate the model's reply. Anything malformed raises AIError rather than being trusted."""
    cleaned = THINK_RE.sub("", raw).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end <= start:
        raise AIError("The model did not return a JSON object.")
    try:
        data = json.loads(cleaned[start:end + 1])
    except ValueError:
        raise AIError("The model returned malformed JSON.") from None
    if not isinstance(data, dict):
        raise AIError("The model returned JSON of the wrong shape.")

    analysis = AIAnalysis(outcome=AIOutcome(status="succeeded"))
    analysis.summary = str(data.get("summary", ""))[:600]
    for item in data.get("assessments") or []:
        if isinstance(item, dict) and item.get("finding_id") in known_ids and item.get("relevance") in RELEVANCE:
            analysis.assessments[item["finding_id"]] = {
                "relevance": item["relevance"], "rationale": str(item.get("rationale", ""))[:300],
            }
    for item in (data.get("additional_concerns") or [])[:MAX_CONCERNS]:
        if not isinstance(item, dict):
            continue
        quote = str(item.get("quote", "")).strip()
        if 3 <= len(quote) <= 200 and "[" not in quote and quote in excerpt:  # must be verbatim text the model saw
            severity = item.get("severity") if item.get("severity") in SEVERITIES else "medium"
            analysis.concerns.append(AIConcern(quote, str(item.get("reason", ""))[:300], severity))
    return analysis


def analyze(
    config: AIConfig,
    masked_text: str,
    findings: Sequence[Finding],
    context: Context,
    focus: str,
    rules: Sequence[Rule],
    consent: bool,
    transport: Transport = http_json,
) -> AIAnalysis:
    """Run the single bounded review request. Never raises: failures become `outcome.status == 'failed'`."""
    if not consent:
        return AIAnalysis(AIOutcome(status="skipped", message="AI analysis was not run: consent was not given."))
    if not config.configured:
        return AIAnalysis(AIOutcome(status="skipped", message="AI analysis was not run: no API key is configured."))
    excerpt = masked_text[: config.max_input_chars]
    truncated = len(masked_text) > len(excerpt)
    payload = {
        "model": config.model,
        "messages": build_messages(excerpt, findings, context, focus, rules),
        "max_tokens": config.max_output_tokens,
        "temperature": 0,
    }
    try:
        reply = transport("POST", f"{config.base_url}/chat/completions", payload, _headers(config), config.timeout_seconds)
        content = reply["choices"][0]["message"]["content"]
        analysis = parse_response(content or "", [f.finding_id for f in findings], excerpt)
    except (AIError, KeyError, IndexError, TypeError) as exc:
        message = str(exc) if isinstance(exc, AIError) else "The endpoint returned an unexpected response shape."
        return AIAnalysis(AIOutcome(status="failed", message=f"AI analysis failed: {message}", model=config.model))
    note = f" Only the first {config.max_input_chars} characters were analyzed." if truncated else ""
    analysis.outcome = AIOutcome(
        status="succeeded", message=f"Reviewed by {config.model}.{note}", model=config.model,
        summary=analysis.summary, truncated=truncated,
    )
    return analysis
