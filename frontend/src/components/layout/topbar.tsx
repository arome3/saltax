"use client";

import { useAgentStatus } from "@/lib/api";
import { StatusPill } from "@/components/saltax/status-pill";
import { WalletConnect } from "@/components/saltax/wallet-connect";
import { CommandPaletteTrigger } from "./command-palette";
import type { AgentHealthStatus } from "@/types";

function deriveHealthStatus(data: ReturnType<typeof useAgentStatus>["data"]): AgentHealthStatus {
  if (!data) return "unknown";
  if (!data.treasury.available) return "degraded";
  if (!data.intelligence.db_initialized) return "halted";
  return "operational";
}

export function Topbar() {
  const { data } = useAgentStatus();
  const status = deriveHealthStatus(data);

  return (
    <header className="sticky top-0 z-40 flex items-center justify-between h-12 border-b bg-background/80 backdrop-blur-sm px-4">
      <div className="flex items-center gap-3">
        <span className="font-semibold text-sm tracking-tight lg:hidden ml-10">
          SaltaX
        </span>
        <StatusPill status={status} />
      </div>

      <div className="flex items-center gap-2">
        <CommandPaletteTrigger />
        <WalletConnect compact />
      </div>
    </header>
  );
}
