import React from "react";
import { Badge } from "./ui/badge";

export function SeverityBadge({ severity }: { severity: string }) {
  let colorClass = "bg-muted text-muted-foreground hover:bg-muted";
  
  if (severity === "critical") {
    colorClass = "bg-destructive/10 text-destructive border-destructive/20 hover:bg-destructive/20";
  } else if (severity === "high") {
    colorClass = "bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20 hover:bg-orange-500/20";
  } else if (severity === "medium") {
    colorClass = "bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-500/20 hover:bg-yellow-500/20";
  } else if (severity === "low") {
    colorClass = "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/20";
  }

  return (
    <Badge variant="outline" className={`font-mono uppercase text-[10px] py-0 px-1.5 ${colorClass}`}>
      {severity}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: string }) {
  let colorClass = "bg-muted text-muted-foreground";
  
  if (status === "open") {
    colorClass = "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20";
  } else if (status === "resolved") {
    colorClass = "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20";
  } else if (status === "false_positive") {
    colorClass = "bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20";
  }

  return (
    <Badge variant="outline" className={`font-medium text-[11px] py-0 px-2 capitalize ${colorClass}`}>
      {status.replace("_", " ")}
    </Badge>
  );
}
