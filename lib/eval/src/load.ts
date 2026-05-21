import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { ChatCaseSchema, TriageCaseSchema, RedteamCaseSchema, type ChatCase, type TriageCase, type RedteamCase } from "./types.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DATASETS = join(HERE, "..", "datasets");

function loadDir<T>(subdir: string, schema: z.ZodType<T>): T[] {
  const dir = join(DATASETS, subdir);
  const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  return files.map((f) => {
    const raw = JSON.parse(readFileSync(join(dir, f), "utf8")) as unknown;
    const parsed = schema.safeParse(raw);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
      throw new Error(`Invalid case ${subdir}/${f}: ${issues}`);
    }
    return parsed.data;
  });
}

export function loadChatCases(): ChatCase[] {
  return loadDir("chat", ChatCaseSchema);
}

export function loadTriageCases(): TriageCase[] {
  return loadDir("triage", TriageCaseSchema);
}

export function loadRedteamCases(): RedteamCase[] {
  return loadDir("redteam", RedteamCaseSchema);
}
