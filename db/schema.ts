import { boolean, integer, jsonb, pgTable, primaryKey, serial, text, timestamp } from "drizzle-orm/pg-core";

export const workspaces = pgTable("workspaces", {
  id: serial().primaryKey(),
  name: text().notNull().unique(),
  salt: text().notNull(),
  hash: text().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const sessions = pgTable("sessions", {
  tokenHash: text("token_hash").primaryKey(),
  workspaceId: integer("workspace_id").notNull().references(() => workspaces.id, { onDelete: "cascade" }),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
});

export const rules = pgTable("rules", {
  workspaceId: integer("workspace_id").notNull().references(() => workspaces.id, { onDelete: "cascade" }),
  ruleId: text("rule_id").notNull(),
  body: jsonb().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
}, (t) => [primaryKey({ columns: [t.workspaceId, t.ruleId] })]);

export const skillStates = pgTable("skill_states", {
  workspaceId: integer("workspace_id").notNull().references(() => workspaces.id, { onDelete: "cascade" }),
  name: text().notNull(),
  enabled: boolean().notNull(),
}, (t) => [primaryKey({ columns: [t.workspaceId, t.name] })]);

export const audits = pgTable("audits", {
  workspaceId: integer("workspace_id").notNull().references(() => workspaces.id, { onDelete: "cascade" }),
  auditId: text("audit_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  body: jsonb().notNull(),
}, (t) => [primaryKey({ columns: [t.workspaceId, t.auditId] })]);
