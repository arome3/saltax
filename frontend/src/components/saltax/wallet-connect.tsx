"use client";

import { useAccount, useConnect, useDisconnect } from "wagmi";
import { Button } from "@/components/ui/button";
import { Wallet, LogOut } from "lucide-react";
import { truncateHash } from "@/lib/utils";

interface WalletConnectProps {
  compact?: boolean;
}

export function WalletConnect({ compact }: WalletConnectProps) {
  const { address, isConnected } = useAccount();
  const { connect, connectors } = useConnect();
  const { disconnect } = useDisconnect();

  if (isConnected && address) {
    return (
      <div className="flex items-center gap-2">
        {!compact && (
          <span className="text-xs font-mono text-muted-foreground">
            {truncateHash(address)}
          </span>
        )}
        <Button
          variant="ghost"
          size={compact ? "icon" : "sm"}
          onClick={() => disconnect()}
          aria-label="Disconnect wallet"
          className={compact ? "h-8 w-8" : undefined}
        >
          {compact ? (
            <LogOut className="h-3.5 w-3.5" />
          ) : (
            <>
              <LogOut className="mr-2 h-3 w-3" />
              Disconnect
            </>
          )}
        </Button>
      </div>
    );
  }

  return (
    <Button
      variant="outline"
      size={compact ? "sm" : "default"}
      onClick={() => {
        const connector = connectors[0];
        if (connector) connect({ connector });
      }}
      className={compact ? "h-8" : undefined}
    >
      <Wallet className="mr-2 h-3.5 w-3.5" />
      {compact ? "Connect" : "Connect Wallet"}
    </Button>
  );
}
