import { seedIfEmpty } from "./seed";

seedIfEmpty()
  .then((seeded) => {
    // eslint-disable-next-line no-console
    console.log(seeded ? "Seeded." : "Already seeded; skipped.");
    process.exit(0);
  })
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error("Seed failed:", err);
    process.exit(1);
  });
