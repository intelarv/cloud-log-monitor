import { describe, expect, it } from "vitest";
import { buildSetupSql } from "@workspace/db";

// M12.2: buildSetupSql has two finding_embeddings layouts. The DEFAULT (no
// opts / tenantPartitioning:false) path MUST stay the single-table layout the
// eval gate depends on; the opt-in path MUST emit a LIST-partitioned table with
// a DEFAULT partition and a composite PK.

describe("buildSetupSql finding_embeddings layout", () => {
  it("defaults to the single-table layout (no partitioning)", () => {
    const sql = buildSetupSql({ embeddingDim: 256 });
    expect(sql).toContain(
      "finding_id text PRIMARY KEY REFERENCES findings(id)",
    );
    expect(sql).not.toContain("PARTITION BY LIST");
    expect(sql).not.toContain("finding_embeddings_default");
    // RLS is present in both layouts.
    expect(sql).toContain("ALTER TABLE finding_embeddings ENABLE ROW LEVEL");
  });

  it("omitting opts entirely is identical to tenantPartitioning:false", () => {
    expect(buildSetupSql({ embeddingDim: 256 })).toBe(
      buildSetupSql({ embeddingDim: 256, tenantPartitioning: false }),
    );
  });

  it("emits a LIST-partitioned table with a DEFAULT partition when opted in", () => {
    const sql = buildSetupSql({
      embeddingDim: 256,
      tenantPartitioning: true,
    });
    expect(sql).toContain("PARTITION BY LIST (tenant_id)");
    expect(sql).toContain(
      "CREATE TABLE finding_embeddings_default PARTITION OF finding_embeddings DEFAULT",
    );
    // Composite PK is mandatory for a LIST-partitioned table.
    expect(sql).toContain("PRIMARY KEY (finding_id, tenant_id)");
    // ivfflat is per-partition (the DEFAULT partition), not on the parent.
    expect(sql).toContain(
      "finding_embeddings_default_vec_idx\n  ON finding_embeddings_default USING ivfflat",
    );
    // Idempotent conversion: only drops when the table exists and is not yet
    // partitioned.
    expect(sql).toContain("IF tbl_exists AND NOT is_partitioned THEN");
    // RLS on parent + default partition.
    expect(sql).toContain("ALTER TABLE finding_embeddings ENABLE ROW LEVEL");
    expect(sql).toContain(
      "ALTER TABLE finding_embeddings_default ENABLE ROW LEVEL",
    );
  });

  it("interpolates the embedding dim in both layouts", () => {
    expect(buildSetupSql({ embeddingDim: 384 })).toContain("vector(384)");
    expect(
      buildSetupSql({ embeddingDim: 384, tenantPartitioning: true }),
    ).toContain("vector(384)");
  });
});

describe("buildSetupSql chat_message_embeddings layout", () => {
  it("defaults to the single-table layout (no partitioning)", () => {
    const sql = buildSetupSql({ embeddingDim: 256 });
    expect(sql).toContain(
      "message_id text PRIMARY KEY REFERENCES chat_messages(id)",
    );
    expect(sql).not.toContain("chat_message_embeddings_default");
    expect(sql).not.toContain("PRIMARY KEY (message_id, tenant_id)");
    // RLS is present in both layouts.
    expect(sql).toContain(
      "ALTER TABLE chat_message_embeddings ENABLE ROW LEVEL",
    );
  });

  it("omitting opts entirely is identical to chatTenantPartitioning:false", () => {
    expect(buildSetupSql({ embeddingDim: 256 })).toBe(
      buildSetupSql({ embeddingDim: 256, chatTenantPartitioning: false }),
    );
  });

  it("emits a LIST-partitioned table with a DEFAULT partition when opted in", () => {
    const sql = buildSetupSql({
      embeddingDim: 256,
      chatTenantPartitioning: true,
    });
    expect(sql).toContain(
      "CREATE TABLE chat_message_embeddings_default PARTITION OF chat_message_embeddings DEFAULT",
    );
    // Composite PK is mandatory for a LIST-partitioned table.
    expect(sql).toContain("PRIMARY KEY (message_id, tenant_id)");
    // ivfflat is per-partition (the DEFAULT partition), not on the parent.
    expect(sql).toContain(
      "chat_message_embeddings_default_vec_idx\n  ON chat_message_embeddings_default USING ivfflat",
    );
    // Idempotent conversion: only drops when the table exists and is not yet
    // partitioned.
    expect(sql).toContain("IF tbl_exists AND NOT is_partitioned THEN");
    // RLS on parent + default partition.
    expect(sql).toContain(
      "ALTER TABLE chat_message_embeddings ENABLE ROW LEVEL",
    );
    expect(sql).toContain(
      "ALTER TABLE chat_message_embeddings_default ENABLE ROW LEVEL",
    );
  });

  it("the two partitioning switches are independent", () => {
    // Chat-only partitioning leaves finding_embeddings single-table.
    const chatOnly = buildSetupSql({
      embeddingDim: 256,
      chatTenantPartitioning: true,
    });
    expect(chatOnly).toContain(
      "finding_id text PRIMARY KEY REFERENCES findings(id)",
    );
    expect(chatOnly).toContain("PRIMARY KEY (message_id, tenant_id)");

    // Finding-only partitioning leaves chat_message_embeddings single-table.
    const findingOnly = buildSetupSql({
      embeddingDim: 256,
      tenantPartitioning: true,
    });
    expect(findingOnly).toContain(
      "message_id text PRIMARY KEY REFERENCES chat_messages(id)",
    );
    expect(findingOnly).toContain("PRIMARY KEY (finding_id, tenant_id)");
  });

  it("interpolates the embedding dim in both layouts", () => {
    expect(
      buildSetupSql({ embeddingDim: 384, chatTenantPartitioning: true }),
    ).toContain("vector(384)");
  });
});
