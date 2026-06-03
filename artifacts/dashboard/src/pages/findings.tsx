import React from "react";
import Layout from "../components/layout";
import {
  useListFindings,
} from "@workspace/api-client-react";
import { useLocation } from "wouter";
import { safeRelativeTime } from "../lib/format";
import { SeverityBadge, StatusBadge } from "../components/severity-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Search, CheckCheck, RotateCcw } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import ResolveFindingModal from "../components/resolve-finding-modal";
import ReopenFindingModal from "../components/reopen-finding-modal";

type StatusFilter = "open" | "resolved" | "false_positive";

export default function Findings() {
  const [, navigate] = useLocation();
  const [status, setStatus] = React.useState<StatusFilter>("open");
  const { data: findings, isLoading } = useListFindings({ status });
  const [resolveId, setResolveId] = React.useState<string | null>(null);
  const [reopenId, setReopenId] = React.useState<string | null>(null);

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Findings</h1>
            <p className="text-muted-foreground">PHI/PII log audits requiring review.</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search fingerprints..." className="pl-8" />
            </div>
          </div>
        </div>

        <Tabs value={status} onValueChange={(v) => setStatus(v as StatusFilter)}>
          <TabsList>
            <TabsTrigger value="open">Open</TabsTrigger>
            <TabsTrigger value="resolved">Resolved</TabsTrigger>
            <TabsTrigger value="false_positive">False positive</TabsTrigger>
          </TabsList>
        </Tabs>

        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">Severity</TableHead>
                  <TableHead>Class</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="max-w-[300px]">Snippet</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead className="text-right">Seen</TableHead>
                  <TableHead className="w-[120px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <TableRow key={i}>
                      <TableCell><Skeleton className="h-5 w-16" /></TableCell>
                      <TableCell><Skeleton className="h-5 w-20" /></TableCell>
                      <TableCell><Skeleton className="h-5 w-16" /></TableCell>
                      <TableCell><Skeleton className="h-5 w-full max-w-[250px]" /></TableCell>
                      <TableCell><Skeleton className="h-5 w-24" /></TableCell>
                      <TableCell className="text-right"><Skeleton className="h-5 w-20 ml-auto" /></TableCell>
                      <TableCell><Skeleton className="h-5 w-16 ml-auto" /></TableCell>
                    </TableRow>
                  ))
                ) : findings?.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                      No {status.replace("_", " ")} findings.
                    </TableCell>
                  </TableRow>
                ) : (
                  findings?.map((finding) => (
                    <TableRow
                      key={finding.id}
                      className="cursor-pointer hover:bg-accent/50 group"
                      onClick={() => navigate(`/findings/${finding.id}`)}
                    >
                      <TableCell>
                        <SeverityBadge severity={finding.severity} />
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {finding.classification}
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={finding.status} />
                      </TableCell>
                      <TableCell className="max-w-[300px]">
                        <span className="block truncate font-mono text-xs text-muted-foreground group-hover:text-foreground transition-colors">
                          {finding.redacted_evidence.snippet}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs">
                        {finding.source}
                      </TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground whitespace-nowrap">
                        {safeRelativeTime(finding.last_seen_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        {finding.status === "open" ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={(e) => {
                              e.stopPropagation();
                              setResolveId(finding.id);
                            }}
                          >
                            <CheckCheck className="h-3.5 w-3.5 mr-1" /> Close
                          </Button>
                        ) : (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={(e) => {
                              e.stopPropagation();
                              setReopenId(finding.id);
                            }}
                          >
                            <RotateCcw className="h-3.5 w-3.5 mr-1" /> Reopen
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {resolveId && (
        <ResolveFindingModal
          open={!!resolveId}
          onOpenChange={(v) => {
            if (!v) setResolveId(null);
          }}
          findingId={resolveId}
        />
      )}

      {reopenId && (
        <ReopenFindingModal
          open={!!reopenId}
          onOpenChange={(v) => {
            if (!v) setReopenId(null);
          }}
          findingId={reopenId}
        />
      )}
    </Layout>
  );
}
