import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { and, eq, gt } from "drizzle-orm";
import { db } from "../db/index.js";
import { sessions, workspaces } from "../db/schema.js";

export const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,39}$/;
export const MIN_PASSPHRASE = 8;
const SESSION_DAYS = 7;

export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export const json = (data: unknown, status = 200) => Response.json(data, { status });

/** Wrap a handler so thrown HttpErrors become JSON error responses and nothing else leaks. */
export function handle(fn: (req: Request) => Promise<Response>) {
  return async (req: Request) => {
    try {
      return await fn(req);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      console.error(err);
      return json({ error: "Something went wrong on the server." }, 500);
    }
  };
}

export async function readJson<T = any>(req: Request): Promise<T> {
  try {
    return (await req.json()) as T;
  } catch {
    throw new HttpError(400, "The request body is not valid JSON.");
  }
}

export function hashPassphrase(passphrase: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scrypt(passphrase, salt, 32, { N: 2 ** 14, r: 8, p: 1 }, (err, key) => (err ? reject(err) : resolve(key))),
  );
}

export const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

export function checkHash(candidate: Buffer, stored: string): boolean {
  const expected = Buffer.from(stored, "hex");
  return expected.length === candidate.length && timingSafeEqual(candidate, expected);
}

export async function newSession(workspaceId: number): Promise<string> {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 86_400_000);
  await db.insert(sessions).values({ tokenHash: sha256(token), workspaceId, expiresAt });
  return token;
}

export function bearer(req: Request): string | null {
  const header = req.headers.get("authorization") || "";
  return header.startsWith("Bearer ") ? header.slice(7).trim() : null;
}

/** Resolve the workspace for the request's session token, or throw 401. */
export async function requireWorkspace(req: Request): Promise<{ id: number; name: string }> {
  const token = bearer(req);
  if (!token) throw new HttpError(401, "Sign in to a workspace first.");
  const [row] = await db
    .select({ id: workspaces.id, name: workspaces.name })
    .from(sessions)
    .innerJoin(workspaces, eq(sessions.workspaceId, workspaces.id))
    .where(and(eq(sessions.tokenHash, sha256(token)), gt(sessions.expiresAt, new Date())));
  if (!row) throw new HttpError(401, "Your session has expired. Sign in again.");
  return row;
}
