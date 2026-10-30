import type { Config } from "@netlify/functions";
import Anthropic from "@anthropic-ai/sdk";
import { HttpError, handle, json, readJson, requireWorkspace } from "../../server/http.js";

/*
 * Contextual review through Netlify AI Gateway.
 * Privacy contract: the browser sends masked text only (every finding already replaced by
 * a [CATEGORY] placeholder) plus policy names, never rule terms. One bounded request per audit.
 * The model can annotate findings and add verbatim-quoted concerns; it can never remove a
 * finding, raise a Critical, or call a document safe.
 */

const MODEL = "claude-haiku-5-5";
const MAX_INPUT_CHARS = 6000;
const MAX_OUTPUT_TOKENS = 1200;
const MAX_CONCERNS = 10;
const RELEVANCE = new Set(["confirmed", "likely", "unlikely"]);
const SEVERITIES = new Set(["low", "medium", "high"]);
const CONTEXTS = new Set(["external client", "public release", "internal team"]);

const SYSTEM_PROMPT =
  "You are a privacy reviewer. You receive a document excerpt in which sensitive values were already " +
  "replaced by placeholders such as [EMAIL] or [API_KEY]. Judge whether the document is appropriate to share " +
  "in the stated context. Reply with ONE JSON object and nothing else, using exactly this shape:\n" +
  '{"summary": str, "assessments": [{"finding_id": str, "relevance": "confirmed|likely|unlikely", "rationale": str}], ' +
  '"additional_concerns": [{"quote": str, "reason": str, "severity": "low|medium|high"}]}\n' +
  "Each quote must be copied exactly from the excerpt and must not contain a placeholder. " +
  "Never state that the document is safe; you only report concerns.";

const anthropic = new Anthropic();

function parseReply(raw: string, knownIds: Set<string>, excerpt: string) {
  const cleaned = raw.replace(/<think>[\s\S]*?<\/think>/gi, "").trim();
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error("The model did not return a JSON object.");
  let data: any;
  try {
    data = JSON.parse(cleaned.slice(start, end + 1));
  } catch {
    throw new Error("The model returned malformed JSON.");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("The model returned JSON of the wrong shape.");

  const assessments: Record<string, { relevance: string; rationale: string }> = {};
  for (const item of Array.isArray(data.assessments) ? data.assessments : []) {
    if (item && knownIds.has(item.finding_id) && RELEVANCE.has(item.relevance)) {
      assessments[item.finding_id] = { relevance: item.relevance, rationale: String(item.rationale ?? "").slice(0, 300) };
    }
  }
  const concerns: { quote: string; reason: string; severity: string }[] = [];
  for (const item of (Array.isArray(data.additional_concerns) ? data.additional_concerns : []).slice(0, MAX_CONCERNS)) {
    if (!item || typeof item !== "object") continue;
    const quote = String(item.quote ?? "").trim();
    // Must be verbatim text the model actually saw, and never a placeholder.
    if (quote.length >= 3 && quote.length <= 200 && !quote.includes("[") && excerpt.includes(quote)) {
      concerns.push({
        quote,
        reason: String(item.reason ?? "").slice(0, 300),
        severity: SEVERITIES.has(item.severity) ? item.severity : "medium",
      });
    }
  }
  return { summary: String(data.summary ?? "").slice(0, 600), assessments, concerns };
}

export default handle(async (req) => {
  if (req.method !== "POST") throw new HttpError(405, "Method not allowed.");
  await requireWorkspace(req);
  const body = await readJson<any>(req);

  const masked = String(body.masked_text ?? "");
  const context = CONTEXTS.has(body.context) ? body.context : "external client";
  const focus = String(body.focus ?? "").slice(0, 300) || "general confidentiality";
  const findings = (Array.isArray(body.findings) ? body.findings : []).slice(0, 300).map((f: any) => ({
    finding_id: String(f.finding_id ?? "").slice(0, 10),
    category: String(f.category ?? "").slice(0, 30),
    severity: String(f.severity ?? "").slice(0, 10),
    excerpt: String(f.excerpt ?? "").slice(0, 200),
  }));
  const policies = (Array.isArray(body.policies) ? body.policies : []).slice(0, 50).map((p: any) => ({
    name: String(p.name ?? "").slice(0, 120),
    description: String(p.description ?? "").slice(0, 400),
  }));

  const excerpt = masked.slice(0, MAX_INPUT_CHARS);
  const truncated = masked.length > excerpt.length;
  const user =
    `Sharing context: ${context}\nSpecial attention: ${focus}\n` +
    `Workspace policies: ${JSON.stringify(policies)}\nDeterministic findings: ${JSON.stringify(findings)}\n` +
    `--- DOCUMENT EXCERPT (masked) ---\n${excerpt}`;

  try {
    const message = await anthropic.messages.create({
      model: MODEL,
      max_tokens: MAX_OUTPUT_TOKENS,
      temperature: 0,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: user }],
    });
    const text = message.content.map((part) => (part.type === "text" ? part.text : "")).join("");
    const analysis = parseReply(text, new Set(findings.map((f: any) => f.finding_id)), excerpt);
    const note = truncated ? ` Only the first ${MAX_INPUT_CHARS} characters were analyzed.` : "";
    return json({ status: "succeeded", message: `Reviewed by ${MODEL}.${note}`, model: MODEL, truncated, ...analysis });
  } catch (err) {
    const reason = err instanceof Error && err.message.startsWith("The model") ? err.message : "The AI service could not be reached.";
    if (!(err instanceof Error && err.message.startsWith("The model"))) console.error(err);
    return json({ status: "failed", message: `AI analysis failed: ${reason}`, model: MODEL, truncated, summary: "", assessments: {}, concerns: [] });
  }
});

export const config: Config = { path: "/api/ai-review" };
