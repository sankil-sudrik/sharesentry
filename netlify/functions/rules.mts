import type { Config } from "@netlify/functions";
import { and, asc, eq } from "drizzle-orm";
import { db } from "../../db/index.js";
import { rules } from "../../db/schema.js";
import { HttpError, handle, json, readJson, requireWorkspace } from "../../server/http.js";
import { cleanRule } from "../../server/validate.js";

export default handle(async (req) => {
  const ws = await requireWorkspace(req);

  if (req.method === "GET") {
    const rows = await db.select({ body: rules.body }).from(rules)
      .where(eq(rules.workspaceId, ws.id)).orderBy(asc(rules.createdAt));
    return json(rows.map((r) => r.body));
  }

  if (req.method === "PUT") {
    const rule = cleanRule(await readJson(req));
    await db.insert(rules).values({ workspaceId: ws.id, ruleId: rule.rule_id, body: rule })
      .onConflictDoUpdate({ target: [rules.workspaceId, rules.ruleId], set: { body: rule } });
    return json(rule);
  }

  if (req.method === "DELETE") {
    const id = new URL(req.url).searchParams.get("id");
    if (!id) throw new HttpError(400, "Missing rule id.");
    await db.delete(rules).where(and(eq(rules.workspaceId, ws.id), eq(rules.ruleId, id)));
    return json({ deleted: true });
  }

  throw new HttpError(405, "Method not allowed.");
});

export const config: Config = { path: "/api/rules" };
