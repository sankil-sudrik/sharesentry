import { HttpError } from "./http.js";

const SEVERITIES = ["low", "medium", "high", "critical"];
const CONTEXTS = ["external client", "public release", "internal team"];
const STATUSES = ["action_required", "review_recommended", "no_issues_detected_within_scope", "incomplete"];
const ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const MAX_AUDIT_BYTES = 400_000;

const str = (value: unknown, max: number) => String(value ?? "").slice(0, max);

export interface RuleBody {
  rule_id: string;
  name: string;
  description: string;
  severity: string;
  terms: string[];
  contexts: string[];
  action: string;
  enabled: boolean;
}

export function cleanRule(input: any): RuleBody {
  if (!input || typeof input !== "object") throw new HttpError(400, "The rule is malformed.");
  const rule_id = str(input.rule_id, 64);
  const name = str(input.name, 120).trim();
  const severity = str(input.severity, 10).toLowerCase();
  if (!ID_RE.test(rule_id)) throw new HttpError(400, "The rule id is invalid.");
  if (!name) throw new HttpError(400, "A rule needs a name.");
  if (!SEVERITIES.includes(severity)) throw new HttpError(400, `Unknown severity: ${severity}`);
  const terms = Array.isArray(input.terms)
    ? input.terms.map((t: unknown) => str(t, 200).trim()).filter(Boolean).slice(0, 200)
    : [];
  const contexts = Array.isArray(input.contexts) ? input.contexts.filter((c: unknown) => CONTEXTS.includes(c as string)) : [];
  return {
    rule_id, name, severity, terms, contexts,
    description: str(input.description, 1000),
    action: str(input.action, 200) || "Redact before sharing",
    enabled: input.enabled !== false,
  };
}

export function cleanAudit(input: any): any {
  if (!input || typeof input !== "object") throw new HttpError(400, "The audit is malformed.");
  if (!ID_RE.test(String(input.audit_id ?? ""))) throw new HttpError(400, "The audit id is invalid.");
  if (!STATUSES.includes(input.status)) throw new HttpError(400, "The audit status is invalid.");
  if (!CONTEXTS.includes(input.context)) throw new HttpError(400, "The audit context is invalid.");
  if (!Array.isArray(input.findings)) throw new HttpError(400, "The audit findings are malformed.");
  if (Number.isNaN(new Date(input.created_at).getTime())) throw new HttpError(400, "The audit date is invalid.");
  if (JSON.stringify(input).length > MAX_AUDIT_BYTES) throw new HttpError(413, "The audit is too large to store.");
  return input;
}
