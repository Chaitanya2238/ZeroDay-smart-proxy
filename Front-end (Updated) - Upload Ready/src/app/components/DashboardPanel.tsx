import type { ReactNode } from "react";

import { cn } from "./ui/utils";

interface DashboardPanelProps {
  children: ReactNode;
  className?: string;
}

export function DashboardPanel({
  children,
  className,
}: DashboardPanelProps) {
  return (
    <div
      className={cn("rounded-xl border bg-card", className)}
      style={{
        borderColor: "#1e2738",
        backgroundColor: "#0f1420",
      }}
    >
      {children}
    </div>
  );
}
