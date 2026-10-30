/**
 * Deterministic detectors. Each returns located Findings with exact offsets into the input text.
 * No detector stores the matched value: callers receive offsets, and `maskText` produces
 * excerpts in which every finding is replaced by a `[CATEGORY]` placeholder.
 */
import { type Category, type Finding, type Rule, type Severity, located, placeholder, rank } from "./models";

const REDACTION_PLACEHOLDER = /\[REDACTED:[A-Z_]+\]/g;
const EXCERPT_RADIUS = 40;

type Span = [number, number];

function finding(category: Category, severity: Severity, [start, end]: Span, rule_id: string, confidence: string, action: string): Finding {
  return {
    finding_id: "", category, severity, start, end, rule_id, confidence, suggested_action: action,
    masked_excerpt: "", source: "deterministic", ai_note: "",
  };
}

function spans(pattern: RegExp, text: string, group?: string): Span[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  const re = new RegExp(pattern.source, group && !flags.includes("d") ? flags + "d" : flags);
  const out: Span[] = [];
  for (const m of text.matchAll(re)) {
    if (group) {
      const span = (m as any).indices?.groups?.[group];
      if (span) out.push([span[0], span[1]]);
    } else {
      out.push([m.index!, m.index! + m[0].length]);
    }
  }
  return out;
}

// ---------------------------------------------------------------- email
const EMAIL_RE = /(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g;

export const detectEmails = (text: string) =>
  spans(EMAIL_RE, text).map((s) => finding("email", "low", s, "builtin.email", "pattern match", "Redact or replace with a role address"));

// ---------------------------------------------------------------- phone
const PHONE_PATTERNS = [
  /(?<![\w+])\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{2,4}){2,4}(?!\w)/g,
  /(?<![\w.])(?:\(\d{3}\)\s?|\d{3}[ .-])\d{3}[ .-]\d{4}(?!\w)/g,
  /(?<![\w+])[6-9]\d{4}[ -]?\d{5}(?!\w)/g,
];
const DOTTED_QUAD_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const PHONE_CONFIDENCE = "uncertain: format-based match, not verified as a phone number";

function plausiblePhone(candidate: string) {
  const digits = candidate.replace(/\D/g, "");
  return digits.length >= 9 && digits.length <= 15 && !DOTTED_QUAD_RE.test(candidate);
}

export const detectPhones = (text: string) =>
  mergeOverlapping(PHONE_PATTERNS.flatMap((p) => spans(p, text))
    .filter(([s, e]) => plausiblePhone(text.slice(s, e)))
    .map((s) => finding("phone", "medium", s, "builtin.phone", PHONE_CONFIDENCE, "Review; redact if it is a real number")));

// ---------------------------------------------------------------- credit card
const CARD_RE = /(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])/g;

export function luhnValid(number: string) {
  const digits = [...number].filter((c) => c >= "0" && c <= "9").map(Number);
  if (digits.length < 13 || digits.length > 19) return false;
  let total = 0;
  digits.reverse().forEach((d, i) => {
    if (i % 2 === 1) d = d > 4 ? d * 2 - 9 : d * 2;
    total += d;
  });
  return total % 10 === 0;
}

export const detectCreditCards = (text: string) =>
  spans(CARD_RE, text).filter(([s, e]) => luhnValid(text.slice(s, e)))
    .map((s) => finding("credit_card", "high", s, "builtin.credit_card", "validated: Luhn checksum passes", "Redact"));

// ---------------------------------------------------------------- API keys / tokens
const NOT_PLACEHOLDER = String.raw`(?!\[REDACTED)`;
const TOKEN_PATTERNS = [
  /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
  /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}/g,
  /\b[pr]k_(?:live|test)_[A-Za-z0-9]{16,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{36,}/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
  /\bAIza[0-9A-Za-z_-]{35}/g,
  /\bnvapi-[A-Za-z0-9_-]{20,}/g,
];
const ASSIGNMENT_RE = new RegExp(
  String.raw`\b(?:api[_-]?key|secret|token|password|passwd|pwd)\b["']?\s*[:=]\s*["']?(?<value>` + NOT_PLACEHOLDER + String.raw`[^\s"',;]{8,})`,
  "gi",
);
const BEARER_RE = new RegExp(String.raw`\bBearer\s+(?<value>` + NOT_PLACEHOLDER + String.raw`[A-Za-z0-9._~+/=-]{20,})`, "gi");

export function detectApiKeys(text: string) {
  const found: [Span, string][] = [
    ...TOKEN_PATTERNS.flatMap((p) => spans(p, text).map((s) => [s, "known token format"] as [Span, string])),
    ...[ASSIGNMENT_RE, BEARER_RE].flatMap((p) => spans(p, text, "value").map((s) => [s, "credential assignment"] as [Span, string])),
  ];
  return mergeOverlapping(found.map(([s, kind]) =>
    finding("api_key", "high", s, "builtin.api_key", `pattern match: ${kind}`, "Revoke if real, then redact")));
}

// ---------------------------------------------------------------- private keys
const PEM_KIND = "(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?";
const PEM_BLOCK_RE = new RegExp(`-----BEGIN ${PEM_KIND}-----[\\s\\S]*?-----END ${PEM_KIND}-----`, "g");
const PEM_HEADER_RE = new RegExp(`-----BEGIN ${PEM_KIND}-----`, "g");

export function detectPrivateKeys(text: string) {
  const blocks = spans(PEM_BLOCK_RE, text);
  const headers = spans(PEM_HEADER_RE, text).filter(([s]) => !blocks.some(([bs, be]) => bs <= s && s < be));
  const action = "Revoke and rotate the key, then remove it";
  return [
    ...blocks.map((s) => finding("private_key", "critical", s, "builtin.private_key", "pattern match: complete PEM block", action)),
    ...headers.map((s) => finding("private_key", "critical", s, "builtin.private_key", "pattern match: PEM header only (block end not found)", action)),
  ];
}

// ---------------------------------------------------------------- cloud access keys
const AWS_KEY_ID_RE = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const AWS_SECRET_RE = new RegExp(
  String.raw`aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?(?<value>` + NOT_PLACEHOLDER + String.raw`[A-Za-z0-9/+=]{40})`,
  "gi",
);

export const detectCloudKeys = (text: string) =>
  mergeOverlapping([...spans(AWS_KEY_ID_RE, text), ...spans(AWS_SECRET_RE, text, "value")].map((s) =>
    finding("cloud_access_key", "critical", s, "builtin.cloud_key", "pattern match: AWS key format", "Deactivate the key in the cloud console, then redact")));

// ---------------------------------------------------------------- internal labels
const LABEL_RE =
  /\b(?:internal use only|internal only|do not distribute|do not share|not for distribution|confidential|proprietary|trade secret|attorney[- ]client privileged)\b/gi;

export const detectInternalLabels = (text: string) =>
  spans(LABEL_RE, text).map((s) => finding("internal_label", "medium", s, "builtin.internal_label", "pattern match: confidentiality marking", "Confirm the document may leave the organization"));

// ---------------------------------------------------------------- user terms
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function detectUserTerms(text: string, rules: Rule[]) {
  const found: Finding[] = [];
  for (const rule of rules) {
    for (const term of new Set(rule.terms.map((t) => t.trim()).filter((t) => t.length >= 2))) {
      const re = new RegExp(`(?<![\\p{L}\\p{N}_])${escapeRe(term)}(?![\\p{L}\\p{N}_])`, "giu");
      for (const s of spans(re, text)) {
        found.push(finding("user_term", rule.severity, s, rule.rule_id, "exact term match (whole word, case-insensitive)", rule.action));
      }
    }
  }
  return found;
}

// ---------------------------------------------------------------- orchestration
const BUILTIN: [Category, (t: string) => Finding[]][] = [
  ["email", detectEmails],
  ["phone", detectPhones],
  ["credit_card", detectCreditCards],
  ["api_key", detectApiKeys],
  ["private_key", detectPrivateKeys],
  ["cloud_access_key", detectCloudKeys],
  ["internal_label", detectInternalLabels],
];

/** Blank out our own redaction placeholders (same length) so re-scans never flag them. */
const neutralize = (text: string) => text.replace(REDACTION_PLACEHOLDER, (m) => " ".repeat(m.length));

export function detect(text: string, categories: Set<Category>, rules: Rule[] = []): Finding[] {
  const scan = neutralize(text);
  const found = BUILTIN.filter(([c]) => categories.has(c)).flatMap(([, fn]) => fn(scan));
  if (categories.has("user_term")) found.push(...detectUserTerms(scan, rules));
  return found;
}

/** Union overlapping spans. The most severe (then longest) member names the merged finding. */
export function mergeOverlapping(findings: Finding[]): Finding[] {
  const loc = findings.filter(located).sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: Finding[] = [];
  let cluster: typeof loc = [];
  let clusterEnd = -1;
  const flush = () => {
    if (!cluster.length) return;
    const winner = cluster.reduce((w, f) =>
      rank(f.severity) > rank(w.severity) || (rank(f.severity) === rank(w.severity) && f.end - f.start > w.end - w.start) ? f : w);
    merged.push({ ...winner, finding_id: "", start: Math.min(...cluster.map((f) => f.start)), end: clusterEnd, masked_excerpt: "", ai_note: "" });
  };
  for (const f of loc) {
    if (cluster.length && f.start < clusterEnd) {
      cluster.push(f);
      clusterEnd = Math.max(clusterEnd, f.end);
      continue;
    }
    flush();
    cluster = [f];
    clusterEnd = f.end;
  }
  flush();
  return [...merged, ...findings.filter((f) => !located(f))];
}

/** Replace every located (non-overlapping) finding with `[CATEGORY]`. Returns masked text and spans per finding index. */
export function maskText(text: string, findings: Finding[]): [string, Map<number, Span>] {
  const order = findings.map((f, i) => i).filter((i) => located(findings[i])).sort((a, b) => findings[a].start! - findings[b].start!);
  const pieces: string[] = [];
  const out = new Map<number, Span>();
  let cursor = 0;
  let length = 0;
  for (const i of order) {
    const f = findings[i];
    const tag = `[${placeholder(f.category)}]`;
    const head = text.slice(cursor, f.start!);
    pieces.push(head, tag);
    out.set(i, [length + head.length, length + head.length + tag.length]);
    length += head.length + tag.length;
    cursor = f.end!;
  }
  pieces.push(text.slice(cursor));
  return [pieces.join(""), out];
}

/** Fill `masked_excerpt` on each located finding and return the fully masked text. */
export function attachExcerpts(text: string, findings: Finding[]): string {
  const [masked, out] = maskText(text, findings);
  for (const [i, [s, e]] of out) {
    findings[i].masked_excerpt = masked.slice(Math.max(0, s - EXCERPT_RADIUS), e + EXCERPT_RADIUS).replace(/\s+/g, " ").trim();
  }
  return masked;
}
