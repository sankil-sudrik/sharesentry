import type { Config } from "@netlify/functions";
import { asc, desc, eq } from "drizzle-orm";
import { db } from "../../db/index.js";
import { audits, rules, skillStates } from "../../db/schema.js";
import { SKILL_NAMES } from "../../server/skills.js";
import { HttpError, handle, json, readJson, requireWorkspace } from "../../server/http.js";
import { cleanAudit, cleanRule } from "../../server/validate.js";

const BACKUP_VERSION = 1;

export default handle(async (req) => {
  const ws = await requireWorkspace(req);

  if (req.method === "GET") {
    const includeTerms = new URL(req.url).searchParams.get("terms") !== "0";
    const [ruleRows, skillRows, auditRows] = await Promise.all([
      db.select({ body: rules.body }).from(rules).where(eq(rules.workspaceId, ws.id)).orderBy(asc(rules.createdAt)),
      db.select().from(skillStates).where(eq(skillStates.workspaceId, ws.id)),
      db.select({ body: audits.body }).from(audits).where(eq(audits.workspaceId, ws.id)).orderBy(desc(audits.createdAt)).limit(1000),
    ]);
    const saved = new Map(skillRows.map((s) => [s.name, s.enabled]));
    return json({
      backup_version: BACKUP_VERSION,
      includes_terms: includeTerms,
      rules: ruleRows.map((r: any) => (includeTerms ? r.body : { ...r.body, terms: [] })),
      skills: Object.fromEntries(SKILL_NAMES.map((n) => [n, saved.get(n) ?? true])),
      audits: auditRows.map((a) => a.body),
    });
  }

  if (req.method === "POST") {
    const data = await readJson<any>(req);
    if (!data || typeof data !== "object" || data.backup_version !== BACKUP_VERSION) {
      throw new HttpError(400, "This is not a ShareSentry backup (unsupported or missing backup_version).");
    }
    // Validate everything before writing anything.
    const ruleList = (Array.isArray(data.rules) ? data.rules : []).map(cleanRule);
    const auditList = (Array.isArray(data.audits) ? data.audits : []).map(cleanAudit);
    const skills = Object.entries(data.skills && typeof data.skills === "object" ? data.skills : {})
      .filter(([name]) => SKILL_NAMES.includes(name));

    for (const rule of ruleList) {
      await db.insert(rules).values({ workspaceId: ws.id, ruleId: rule.rule_id, body: rule })
        .onConflictDoUpdate({ target: [rules.workspaceId, rules.ruleId], set: { body: rule } });
    }
    for (const audit of auditList) {
      await db.insert(audits).values({ workspaceId: ws.id, auditId: audit.audit_id, createdAt: new Date(audit.created_at), body: audit })
        .onConflictDoUpdate({ target: [audits.workspaceId, audits.auditId], set: { body: audit } });
    }
    for (const [name, enabled] of skills) {
      await db.insert(skillStates).values({ workspaceId: ws.id, name, enabled: Boolean(enabled) })
        .onConflictDoUpdate({ target: [skillStates.workspaceId, skillStates.name], set: { enabled: Boolean(enabled) } });
    }
    return json({ rules: ruleList.length, audits: auditList.length, skills: skills.length });
  }

  throw new HttpError(405, "Method not allowed.");
});

export const config: Config = { path: "/api/backup" };
