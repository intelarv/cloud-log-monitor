/**
 * Validates every case file in datasets/ against its Zod schema.
 * Runs in CI as the cheap pre-flight check before any agent target exists.
 */
import { loadChatCases, loadTriageCases, loadRedteamCases } from "./load.js";

const chat = loadChatCases();
const triage = loadTriageCases();
const redteam = loadRedteamCases();

console.log(`chat:     ${chat.length} cases`);
console.log(`triage:   ${triage.length} cases`);
console.log(`redteam:  ${redteam.length} cases`);

const idSet = new Set<string>();
for (const c of [...chat, ...triage, ...redteam]) {
  if (idSet.has(c.id)) {
    console.error(`duplicate id: ${c.id}`);
    process.exit(1);
  }
  idSet.add(c.id);
}

console.log("ok");
