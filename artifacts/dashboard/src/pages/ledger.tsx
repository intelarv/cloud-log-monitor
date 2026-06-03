import React from "react";
import { useSearch, Link } from "wouter";
import Layout from "../components/layout";
import { useListLedger, useVerifyLedger, useListLedgerCheckpoints, getListLedgerCheckpointsQueryKey, getVerifyLedgerQueryKey } from "@workspace/api-client-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck, ShieldAlert, Key, Link as LinkIcon, ChevronDown, ChevronRight, Activity, ExternalLink, CheckCircle2 } from "lucide-react";
import { safeTimestamp } from "../lib/format";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Skeleton } from "@/components/ui/skeleton";

export default function Ledger() {
  // Deep-link support: a `?seq=<n>` query param (e.g. from a finding's history
  // timeline) focuses the list on a specific ledger entry. We widen the fetch
  // window so the target row is loaded even if it falls outside the default
  // page, then auto-expand and scroll to it below.
  const search = useSearch();
  const targetSeq = React.useMemo(() => {
    const raw = new URLSearchParams(search).get("seq");
    if (!raw) return null;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : null;
  }, [search]);

  // `?actor=<id>` pivots the ledger to one human actor's activity (e.g. from
  // clicking an actor in a row — "show me everything this analyst did"). The
  // server filters by actor id so the trail is complete (paginated over the
  // actor's full history), not just whatever falls in the most-recent window.
  const actorFilter = React.useMemo(
    () => new URLSearchParams(search).get("actor") || null,
    [search],
  );

  // Page size per fetch. We paginate forward over the actor's (or the whole
  // tenant's) trail using the server's `after_seq` cursor, accumulating pages
  // client-side so "load more" reveals the complete history instead of a single
  // capped window.
  const PAGE_SIZE = 100;

  // The first cursor for a given view. For a deep-link target we widen the
  // initial window so the focused row loads even if it's outside the default
  // first page; otherwise we start from the beginning of the (tenant/actor)
  // chain. Forward pagination then continues from the last loaded seq.
  const baseCursor = React.useMemo(() => {
    if (actorFilter) return 0;
    if (targetSeq != null) return Math.max(0, targetSeq - 26);
    return 0;
  }, [actorFilter, targetSeq]);

  // A stable identity for the current "view" (actor pivot / deep-link target /
  // default). When it changes we reset the accumulated pages and cursor.
  const viewKey = `${actorFilter ?? ""}|${targetSeq ?? ""}`;

  const [cursor, setCursor] = React.useState(baseCursor);
  const [accumulated, setAccumulated] = React.useState<any[]>([]);
  const [reachedEnd, setReachedEnd] = React.useState(false);

  React.useEffect(() => {
    setCursor(baseCursor);
    setAccumulated([]);
    setReachedEnd(false);
  }, [viewKey, baseCursor]);

  const listParams = React.useMemo(() => {
    const p: { limit: number; after_seq: number; actor?: string } = {
      limit: PAGE_SIZE,
      after_seq: cursor,
    };
    if (actorFilter) p.actor = actorFilter;
    return p;
  }, [cursor, actorFilter]);

  const { data: ledgerPage, isFetching } = useListLedger(listParams);

  // Append each freshly-fetched page into the accumulated list (dedup by seq,
  // kept ascending). A short page (< PAGE_SIZE) means we've reached the end of
  // this view's history.
  React.useEffect(() => {
    if (!ledgerPage) return;
    setAccumulated((prev) => {
      const seen = new Set(prev.map((e) => e.seq));
      const merged = [...prev];
      for (const e of ledgerPage.entries) {
        if (!seen.has(e.seq)) merged.push(e);
      }
      merged.sort((a, b) => a.seq - b.seq);
      return merged;
    });
    setReachedEnd(ledgerPage.entries.length < PAGE_SIZE);
  }, [ledgerPage]);

  const visibleEntries = accumulated;

  // Skeletons only on the very first load of a view; subsequent "load more"
  // fetches keep the already-loaded rows visible with an inline spinner.
  const showInitialSkeleton = isFetching && accumulated.length === 0;

  const handleLoadMore = React.useCallback(() => {
    const last = accumulated[accumulated.length - 1];
    if (last) setCursor(last.seq);
  }, [accumulated]);

  // If a deep-link target was requested but it isn't present in the loaded
  // window (too old to be in range, or doesn't exist for this tenant), surface
  // a notice instead of silently showing the list with nothing highlighted.
  // The initial cursor centers the first page on the target, so once that page
  // has loaded the target is present iff it exists for this tenant; forward
  // "load more" only adds higher seqs and never changes this answer.
  const targetMissing = React.useMemo(() => {
    if (targetSeq == null || isFetching || accumulated.length === 0) return false;
    return !accumulated.some((e) => e.seq === targetSeq);
  }, [targetSeq, isFetching, accumulated]);

  const actorFilterLabel = React.useMemo<string | null>(() => {
    if (!actorFilter) return null;
    const match = accumulated.find(
      (e) => e.actor?.kind === "human" && e.actor?.id === actorFilter,
    );
    const dn = (match?.actor as { display_name?: string } | undefined)?.display_name;
    return dn || actorFilter;
  }, [actorFilter, accumulated]);
  
  const verifyChain = useVerifyLedger({ query: { enabled: false, queryKey: getVerifyLedgerQueryKey() } });
  const { data: checkpointsPage, refetch: refetchCheckpoints, isFetching: isVerifyingCheckpoints } = useListLedgerCheckpoints(
    { limit: 10, verify: "1" }, 
    { query: { enabled: false, queryKey: getListLedgerCheckpointsQueryKey({ limit: 10, verify: "1" }) } }
  );

  const handleVerifyChain = async () => {
    await verifyChain.refetch();
  };

  const getEventColor = (eventType: string) => {
    if (eventType.startsWith("break_glass")) return "text-orange-500 bg-orange-500/10 border-orange-500/20";
    if (eventType.startsWith("auth.step_up")) return "text-yellow-500 bg-yellow-500/10 border-yellow-500/20";
    if (eventType.includes("invalid") || eventType.includes("rejected") || eventType.includes("regression")) return "text-destructive bg-destructive/10 border-destructive/20";
    return "text-muted-foreground bg-muted border-border";
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Audit Ledger</h1>
          <p className="text-muted-foreground">Tamper-evident, cryptographically chained record of all system activity.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center justify-between">
                <span>Cryptographic Chain</span>
                <Button size="sm" variant="outline" onClick={handleVerifyChain} disabled={verifyChain.isFetching}>
                  <LinkIcon className="h-4 w-4 mr-2" />
                  {verifyChain.isFetching ? "Verifying..." : "Verify Chain"}
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {verifyChain.data ? (
                <div className={`p-4 rounded-md border ${verifyChain.data.ok ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-700 dark:text-emerald-400" : "bg-destructive/10 border-destructive/20 text-destructive"}`}>
                  <div className="flex items-center gap-2 font-semibold mb-1">
                    {verifyChain.data.ok ? <ShieldCheck className="h-5 w-5" /> : <ShieldAlert className="h-5 w-5" />}
                    {verifyChain.data.ok ? "Chain Intact" : "Chain Broken"}
                  </div>
                  <div className="text-sm opacity-90 font-mono">
                    Walked {verifyChain.data.walked} entries. Head seq: {verifyChain.data.head_seq}.
                  </div>
                  {!verifyChain.data.ok && verifyChain.data.errors && (
                    <ul className="mt-2 text-xs list-disc pl-5 opacity-90 space-y-1">
                      {verifyChain.data.errors.map((e, i) => <li key={i}>{e}</li>)}
                    </ul>
                  )}
                </div>
              ) : (
                <div className="h-[76px] flex items-center justify-center text-sm text-muted-foreground border rounded-md border-dashed">
                  Click verify to walk the hash chain
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center justify-between">
                <span>Notarized Checkpoints</span>
                <Button size="sm" variant="outline" onClick={() => refetchCheckpoints()} disabled={isVerifyingCheckpoints}>
                  <Key className="h-4 w-4 mr-2" />
                  {isVerifyingCheckpoints ? "Checking..." : "Verify Signatures"}
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {checkpointsPage?.verify ? (
                <div className={`p-4 rounded-md border ${checkpointsPage.verify.ok ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-700 dark:text-emerald-400" : "bg-destructive/10 border-destructive/20 text-destructive"}`}>
                  <div className="flex items-center gap-2 font-semibold mb-1">
                    {checkpointsPage.verify.ok ? <ShieldCheck className="h-5 w-5" /> : <ShieldAlert className="h-5 w-5" />}
                    {checkpointsPage.verify.ok ? "Signatures Valid" : "Signature Verification Failed"}
                  </div>
                  <div className="text-sm opacity-90 font-mono">
                    Checked {checkpointsPage.verify.checked} checkpoints against public keys.
                  </div>
                  {!checkpointsPage.verify.ok && checkpointsPage.verify.errors && (
                    <ul className="mt-2 text-xs list-disc pl-5 opacity-90 space-y-1">
                      {checkpointsPage.verify.errors.map((e, i) => <li key={i}>{e}</li>)}
                    </ul>
                  )}
                </div>
              ) : (
                <div className="h-[76px] flex items-center justify-center text-sm text-muted-foreground border rounded-md border-dashed">
                  Click verify to check checkpoint signatures
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {actorFilter && (
          <div className="flex items-center justify-between gap-2 p-3 rounded-md border bg-primary/5 border-primary/20 text-sm">
            <span className="flex items-center gap-2">
              <Activity className="h-4 w-4 shrink-0 text-primary" />
              Showing activity for actor{" "}
              <span className="font-mono font-semibold">{actorFilterLabel}</span>
            </span>
            <Link href="/ledger" className="text-primary hover:underline shrink-0">
              Clear filter
            </Link>
          </div>
        )}

        {actorFilter && !isFetching && visibleEntries.length === 0 && (
          <div className="flex items-center gap-2 p-3 rounded-md border bg-yellow-500/10 border-yellow-500/20 text-yellow-700 dark:text-yellow-400 text-sm">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span>
              No activity recorded for this actor in your tenant.
            </span>
          </div>
        )}

        {targetMissing && (
          <div className="flex items-center gap-2 p-3 rounded-md border bg-yellow-500/10 border-yellow-500/20 text-yellow-700 dark:text-yellow-400 text-sm">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span>
              Entry #{targetSeq} is not in the current view. It may be outside the loaded range or unavailable for your tenant.
            </span>
          </div>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Ledger Entries</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[80px]">Seq</TableHead>
                  <TableHead className="w-[180px]">Timestamp</TableHead>
                  <TableHead>Event Type</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Subject</TableHead>
                  <TableHead className="w-[150px]">Hash</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {showInitialSkeleton ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <TableRow key={i}>
                      <TableCell><Skeleton className="h-4 w-10" /></TableCell>
                      <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                      <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                      <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                      <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                      <TableCell><Skeleton className="h-4 w-20" /></TableCell>
                    </TableRow>
                  ))
                ) : (
                  visibleEntries.map((entry) => (
                    <LedgerRow
                      key={entry.seq}
                      entry={entry}
                      colorClass={getEventColor(entry.event_type)}
                      isTarget={targetSeq != null && entry.seq === targetSeq}
                      activeActorFilter={actorFilter}
                    />
                  ))
                )}
              </TableBody>
            </Table>
            {!showInitialSkeleton && visibleEntries.length > 0 && (
              <div className="flex flex-col items-center justify-center gap-2 border-t p-4">
                {!reachedEnd ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleLoadMore}
                    disabled={isFetching}
                  >
                    {isFetching ? (
                      <>
                        <ChevronDown className="h-4 w-4 mr-2 animate-pulse" />
                        Loading…
                      </>
                    ) : (
                      <>
                        <ChevronDown className="h-4 w-4 mr-2" />
                        Load newer entries
                      </>
                    )}
                  </Button>
                ) : (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <CheckCircle2 className="h-4 w-4" />
                    End of history — {visibleEntries.length}{" "}
                    {visibleEntries.length === 1 ? "entry" : "entries"} loaded.
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </Layout>
  );
}

function LedgerRow({ entry, colorClass, isTarget = false, activeActorFilter = null }: { entry: any, colorClass: string, isTarget?: boolean, activeActorFilter?: string | null }) {
  const [isOpen, setIsOpen] = React.useState(isTarget);
  const rowRef = React.useRef<HTMLTableRowElement>(null);
  const isFindingSubject = entry.subject_type === "finding" && !!entry.subject_id;
  const isChatSessionSubject = entry.subject_type === "chat_session" && !!entry.subject_id;

  // Only human actors map to a "user activity" view; agent/system actors have
  // no per-user pivot, so they stay plain text. Don't self-link the actor we're
  // already filtering by.
  const isUserActor = entry.actor?.kind === "human" && !!entry.actor?.id;
  const actorLabel = entry.actor?.display_name || entry.actor?.id || entry.actor?.kind || JSON.stringify(entry.actor);
  const actorLinkable = isUserActor && entry.actor.id !== activeActorFilter;

  // When deep-linked to this entry, expand it and bring it into view.
  React.useEffect(() => {
    if (isTarget) {
      setIsOpen(true);
      rowRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [isTarget]);

  return (
    <>
      <TableRow
        ref={rowRef}
        className={`font-mono text-xs cursor-pointer hover:bg-muted/50 ${isTarget ? "bg-primary/5 outline outline-2 outline-primary/40" : ""}`}
        onClick={() => setIsOpen(!isOpen)}
      >
        <TableCell>{entry.seq}</TableCell>
        <TableCell className="text-muted-foreground">{safeTimestamp(entry.ts)}</TableCell>
        <TableCell>
          <Badge variant="outline" className={colorClass}>{entry.event_type}</Badge>
        </TableCell>
        <TableCell className="max-w-[150px] truncate">
          {actorLinkable ? (
            <Link
              href={`/ledger?actor=${encodeURIComponent(entry.actor.id)}`}
              onClick={(e) => e.stopPropagation()}
              className="inline-flex items-center gap-1 hover:text-foreground hover:underline"
              title="Show this user's activity"
            >
              {actorLabel}
              <Activity className="h-3 w-3" />
            </Link>
          ) : (
            actorLabel
          )}
        </TableCell>
        <TableCell className="max-w-[200px] truncate text-muted-foreground">
          {entry.subject_type ? (
            isFindingSubject ? (
              <Link
                href={`/findings/${entry.subject_id}`}
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 hover:text-foreground hover:underline"
                title="Open this finding's detail page"
              >
                {`${entry.subject_type}:${entry.subject_id?.substring(0, 8)}`}
                <ExternalLink className="h-3 w-3" />
              </Link>
            ) : isChatSessionSubject ? (
              <Link
                href={`/chat?session=${encodeURIComponent(entry.subject_id)}`}
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 hover:text-foreground hover:underline"
                title="Open this chat session"
              >
                {`${entry.subject_type}:${entry.subject_id?.substring(0, 8)}`}
                <ExternalLink className="h-3 w-3" />
              </Link>
            ) : (
              `${entry.subject_type}:${entry.subject_id?.substring(0, 8)}`
            )
          ) : (
            "—"
          )}
        </TableCell>
        <TableCell className="flex items-center gap-2 text-muted-foreground">
          {entry.hash.substring(0, 16)}...
          {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </TableCell>
      </TableRow>
      {isOpen && (
        <TableRow className="bg-muted/30">
          <TableCell colSpan={6} className="p-4 border-b">
            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
              <div>
                <div className="text-muted-foreground mb-1 font-sans font-semibold">Payload</div>
                <pre className="bg-background p-3 rounded border text-foreground overflow-x-auto">
                  {JSON.stringify(entry.payload, null, 2)}
                </pre>
              </div>
              <div className="space-y-4">
                <div>
                  <div className="text-muted-foreground mb-1 font-sans font-semibold">Full Actor</div>
                  <pre className="bg-background p-3 rounded border text-foreground overflow-x-auto">
                    {JSON.stringify(entry.actor, null, 2)}
                  </pre>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1 font-sans font-semibold">Chain Links</div>
                  <div className="bg-background p-3 rounded border text-muted-foreground space-y-1">
                    <div className="flex gap-2"><span className="text-foreground w-12">Prev:</span> {entry.prev_hash}</div>
                    <div className="flex gap-2"><span className="text-foreground w-12">Hash:</span> {entry.hash}</div>
                  </div>
                </div>
                {isUserActor && (
                  <div>
                    <div className="text-muted-foreground mb-1 font-sans font-semibold">Actor activity</div>
                    <Link
                      href={`/ledger?actor=${encodeURIComponent(entry.actor.id)}`}
                      className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
                      title="Show this user's activity"
                    >
                      <span className="font-mono">View activity for {actorLabel}</span>
                      <Activity className="h-3 w-3" />
                    </Link>
                  </div>
                )}
                {isFindingSubject && (
                  <div>
                    <div className="text-muted-foreground mb-1 font-sans font-semibold">Subject</div>
                    <Link
                      href={`/findings/${entry.subject_id}`}
                      className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
                      title="Open this finding's detail page"
                    >
                      <span className="font-mono">View finding {entry.subject_id}</span>
                      <ExternalLink className="h-3 w-3" />
                    </Link>
                  </div>
                )}
                {isChatSessionSubject && (
                  <div>
                    <div className="text-muted-foreground mb-1 font-sans font-semibold">Subject</div>
                    <Link
                      href={`/chat?session=${encodeURIComponent(entry.subject_id)}`}
                      className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
                      title="Open this chat session"
                    >
                      <span className="font-mono">Open chat session {entry.subject_id}</span>
                      <ExternalLink className="h-3 w-3" />
                    </Link>
                  </div>
                )}
              </div>
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}
