/** Domain types shared by every layer. Plain JSON-friendly objects mirroring the Python package. */

export const SEVERITY = { low: 1, medium: 2, high: 3, critical: 4 } as const;
export type Severity = keyof typeof SEVERITY;
export const SEVERITIES_DESC: Severity[] = ["critical", "high", "medium", "low"];

export const rank = (s: Severity) => SEVERITY[s];
export const raisedTo = (s: Severity, floor: Severity): Severity => (rank(s) >= rank(floor) ? s : floor);
export const lowered = (s: Severity): Severity => SEVERITIES_DESC[Math.min(3, SEVERITIES_DESC.indexOf(s) + 1)];
export const label = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

export type Category =
  | "email" | "phone" | "credit_card" | "api_key" | "private_key"
  | "cloud_access_key" | "user_term" | "internal_label" | "ai_concern";

export const CATEGORY_LABEL: Record<Category, string> = {
  email: "Email address",
  phone: "Phone number",
  credit_card: "Payment card",
  api_key: "API key / token",
  private_key: "Private key",
  cloud_access_key: "Cloud access key",
  user_term: "Your rule term",
  internal_label: "Confidentiality label",
  ai_concern: "AI concern",
};

export const placeholder = (c: Category) => c.toUpperCase();

export type Context = "external client" | "public release" | "internal team";
export const CONTEXTS: Context[] = ["external client", "public release", "internal team"];

export type Status = "action_required" | "review_recommended" | "no_issues_detected_within_scope" | "incomplete";
export const STATUS_LABEL: Record<Status, string> = {
  action_required: "Action required",
  review_recommended: "Review recommended",
  no_issues_detected_within_scope: "No issues detected within scope",
  incomplete: "Incomplete: part of the document could not be inspected",
};

export interface Finding {
  finding_id: string;
  category: Category;
  severity: Severity;
  start: number | null;
  end: number | null;
  rule_id: string;
  confidence: string;
  suggested_action: string;
  masked_excerpt: string;
  source: "deterministic" | "ai";
  ai_note: string;
}

export const located = (f: Finding): f is Finding & { start: number; end: number } => f.start !== null && f.end !== null;

export interface Rule {
  rule_id: string;
  name: string;
  description: string;
  severity: Severity;
  terms: string[];
  contexts: Context[];
  action: string;
  enabled: boolean;
}

export const ruleApplies = (r: Rule, c: Context) => r.enabled && (!r.contexts.length || r.contexts.includes(c));

export type SegmentRef =
  | { kind: "text" }
  | { kind: "csv"; row: number; col: number }
  | { kind: "docx"; part: string; index: number }
  | { kind: "pdf"; page: number };

export interface Segment {
  text: string;
  start: number;
  ref: SegmentRef;
}

export interface Doc {
  name: string;
  fmt: string;
  segments: Segment[];
  scope_notes: string[];
  incomplete_reasons: string[];
  raw: Uint8Array;
  meta: { rows?: string[][]; delimiter?: string; encoding?: string; page_count?: number };
}

export const docText = (d: Doc) => d.segments.map((s) => s.text).join("\n");

export function setSegments(doc: Doc, items: [string, SegmentRef][]) {
  let cursor = 0;
  doc.segments = items.map(([text, ref]) => {
    const seg = { text, start: cursor, ref };
    cursor += text.length + 1;
    return seg;
  });
}

export interface AIOutcome {
  status: "skipped" | "succeeded" | "failed";
  message: string;
  model: string | null;
  summary: string;
  truncated: boolean;
}

export interface Verification {
  output_name: string;
  redacted_count: number;
  remaining_count: number;
  remaining: Finding[];
}

export interface Audit {
  audit_id: string;
  document_name: string;
  fmt: string;
  skill: string;
  context: Context;
  status: Status;
  findings: Finding[];
  scope_notes: string[];
  incomplete_reasons: string[];
  ai: AIOutcome;
  verification: Verification | null;
  created_at: string;
}

export const countBy = (a: Audit, s: Severity) => a.findings.filter((f) => f.severity === s).length;

export const uid = (n = 12) =>
  Array.from(crypto.getRandomValues(new Uint8Array(n / 2)), (b) => b.toString(16).padStart(2, "0")).join("");
