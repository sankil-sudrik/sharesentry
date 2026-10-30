CREATE TABLE "audits" (
	"workspace_id" integer,
	"audit_id" text,
	"created_at" timestamp with time zone NOT NULL,
	"body" jsonb NOT NULL,
	CONSTRAINT "audits_pkey" PRIMARY KEY("workspace_id","audit_id")
);
--> statement-breakpoint
CREATE TABLE "rules" (
	"workspace_id" integer,
	"rule_id" text,
	"body" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "rules_pkey" PRIMARY KEY("workspace_id","rule_id")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"token_hash" text PRIMARY KEY,
	"workspace_id" integer NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "skill_states" (
	"workspace_id" integer,
	"name" text,
	"enabled" boolean NOT NULL,
	CONSTRAINT "skill_states_pkey" PRIMARY KEY("workspace_id","name")
);
--> statement-breakpoint
CREATE TABLE "workspaces" (
	"id" serial PRIMARY KEY,
	"name" text NOT NULL UNIQUE,
	"salt" text NOT NULL,
	"hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audits" ADD CONSTRAINT "audits_workspace_id_workspaces_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "rules" ADD CONSTRAINT "rules_workspace_id_workspaces_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_workspace_id_workspaces_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "skill_states" ADD CONSTRAINT "skill_states_workspace_id_workspaces_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE;