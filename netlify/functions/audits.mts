import type { Config } from "@netlify/functions";
import { and, desc, eq } from "drizzle-orm";
import { db } from "../../db/index.js";
import { audits } from "../../db/schema.js";
import { HttpError, handle, json, readJson, requireWorkspace } from "../../server/http.js";
import { cleanAudit } from "../../server/validate.js";

export default handle(async (req) => {
  const ws = await requireWorkspace(req);

  if (req.method === "GET") {
    const rows = await db.select({ body: audits.body }).from(audits)
      .where(eq(audits.workspaceId, ws.id)).orderBy(desc(audits.createdAt)).limit(100);
    return json(rows.map((r) => r.body));
  }

  if (req.method === "PUT") {
    const audit = cleanAudit(await readJson(req));
    const createdAt = new Date(audit.created_at);
    await db.insert(audits).values({ workspaceId: ws.id, auditId: audit.audit_id, createdAt, body: audit })
      .onConflictDoUpdate({ target: [audits.workspaceId, audits.auditId], set: { body: audit } });
    return json({ saved: true });
  }

  if (req.method === "DELETE") {
    const id = new URL(req.url).searchParams.get("id");
    if (!id) throw new HttpError(400, "Missing audit id.");
    await db.delete(audits).where(and(eq(audits.workspaceId, ws.id), eq(audits.auditId, id)));
    return json({ deleted: true });
  }

  throw new HttpError(405, "Method not allowed.");
});

export const config: Config = { path: "/api/audits" };
