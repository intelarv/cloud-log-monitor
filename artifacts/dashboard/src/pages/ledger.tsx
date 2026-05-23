import React from "react";
import Layout from "../components/layout";
import { useListLedger, useVerifyLedger, useListLedgerCheckpoints, getListLedgerCheckpointsQueryKey, getVerifyLedgerQueryKey } from "@workspace/api-client-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck, ShieldAlert, Key, Link as LinkIcon, ChevronDown, ChevronRight, Activity } from "lucide-react";
import { format } from "date-fns";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Skeleton } from "@/components/ui/skeleton";

export default function Ledger() {
  const { data: ledgerPage, isLoading } = useListLedger({ limit: 50 });
  
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
                {isLoading ? (
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
                  ledgerPage?.entries.map((entry) => (
                    <LedgerRow key={entry.seq} entry={entry} colorClass={getEventColor(entry.event_type)} />
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </Layout>
  );
}

function LedgerRow({ entry, colorClass }: { entry: any, colorClass: string }) {
  const [isOpen, setIsOpen] = React.useState(false);
  
  return (
    <>
      <TableRow className="font-mono text-xs cursor-pointer hover:bg-muted/50" onClick={() => setIsOpen(!isOpen)}>
        <TableCell>{entry.seq}</TableCell>
        <TableCell className="text-muted-foreground">{format(new Date(entry.ts), "yyyy-MM-dd HH:mm:ss")}</TableCell>
        <TableCell>
          <Badge variant="outline" className={colorClass}>{entry.event_type}</Badge>
        </TableCell>
        <TableCell className="max-w-[150px] truncate">
          {entry.actor.sub || entry.actor.role || JSON.stringify(entry.actor)}
        </TableCell>
        <TableCell className="max-w-[200px] truncate text-muted-foreground">
          {entry.subject_type ? `${entry.subject_type}:${entry.subject_id?.substring(0,8)}` : "—"}
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
              </div>
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}
