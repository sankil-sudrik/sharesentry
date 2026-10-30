import type { Config } from "@netlify/functions";
import { db } from "../../db/index.js";
import { skillStates } from "../../db/schema.js";
import { SKILL_NAMES } from "../../server/skills.js";
import { HttpError, handle, json, readJson, requireWorkspace } from "../../server/http.js";

export default handle(async (req) => {
  if (req.method !== "PUT") throw new HttpError(405, "Method not allowed.");
  const ws = await requireWorkspace(req);
  const { name, enabled } = await readJson<{ name?: string; enabled?: boolean }>(req);
  if (!name || !SKILL_NAMES.includes(name)) throw new HttpError(400, "Unknown skill.");
  await db.insert(skillStates).values({ workspaceId: ws.id, name, enabled: Boolean(enabled) })
    .onConflictDoUpdate({ target: [skillStates.workspaceId, skillStates.name], set: { enabled: Boolean(enabled) } });
  return json({ name, enabled: Boolean(enabled) });
});

export const config: Config = { path: "/api/skills" };
