import type { Config } from "@netlify/functions";
import { randomBytes } from "node:crypto";
import { eq, lt } from "drizzle-orm";
import { db } from "../../db/index.js";
import { sessions, skillStates, workspaces } from "../../db/schema.js";
import { SKILL_NAMES } from "../../server/skills.js";
import {
  HttpError, MIN_PASSPHRASE, NAME_RE, bearer, checkHash, handle, hashPassphrase, json, newSession, readJson,
  requireWorkspace, sha256,
} from "../../server/http.js";

const AUTH_FAILED = "Unknown workspace or wrong passphrase.";

async function skillMap(workspaceId: number) {
  const saved = await db.select().from(skillStates).where(eq(skillStates.workspaceId, workspaceId));
  const byName = new Map(saved.map((s) => [s.name, s.enabled]));
  return Object.fromEntries(SKILL_NAMES.map((n) => [n, byName.get(n) ?? true]));
}

export default handle(async (req) => {
  if (req.method === "GET") {
    const ws = await requireWorkspace(req);
    return json({ name: ws.name, skills: await skillMap(ws.id) });
  }

  if (req.method === "DELETE") {
    const ws = await requireWorkspace(req);
    await db.delete(workspaces).where(eq(workspaces.id, ws.id));
    return json({ deleted: true });
  }

  if (req.method !== "POST") throw new HttpError(405, "Method not allowed.");
  const body = await readJson<{ action?: string; name?: string; passphrase?: string }>(req);

  if (body.action === "logout") {
    const token = bearer(req);
    if (token) await db.delete(sessions).where(eq(sessions.tokenHash, sha256(token)));
    return json({ ok: true });
  }

  const name = String(body.name ?? "").trim().toLowerCase();
  const passphrase = String(body.passphrase ?? "");
  if (!NAME_RE.test(name)) throw new HttpError(400, "Workspace names use 1-40 letters, digits, '-' or '_'.");

  // Opportunistic cleanup of expired sessions.
  await db.delete(sessions).where(lt(sessions.expiresAt, new Date()));

  if (body.action === "create") {
    if (passphrase.length < MIN_PASSPHRASE) {
      throw new HttpError(400, `The passphrase must be at least ${MIN_PASSPHRASE} characters.`);
    }
    const salt = randomBytes(16);
    const hash = (await hashPassphrase(passphrase, salt)).toString("hex");
    const [created] = await db
      .insert(workspaces)
      .values({ name, salt: salt.toString("hex"), hash })
      .onConflictDoNothing()
      .returning({ id: workspaces.id });
    if (!created) throw new HttpError(409, "A workspace with this name already exists.");
    return json({ token: await newSession(created.id), name, skills: await skillMap(created.id) }, 201);
  }

  if (body.action === "open") {
    const [ws] = await db.select().from(workspaces).where(eq(workspaces.name, name));
    if (!ws) {
      await hashPassphrase(passphrase, randomBytes(16)); // keep timing similar for unknown names
      throw new HttpError(401, AUTH_FAILED);
    }
    const candidate = await hashPassphrase(passphrase, Buffer.from(ws.salt, "hex"));
    if (!checkHash(candidate, ws.hash)) throw new HttpError(401, AUTH_FAILED);
    return json({ token: await newSession(ws.id), name, skills: await skillMap(ws.id) });
  }

  throw new HttpError(400, "Unknown action.");
});

export const config: Config = { path: "/api/workspace" };
