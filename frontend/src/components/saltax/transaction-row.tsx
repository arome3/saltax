import { Badge } from "@/components/ui/badge";
import { formatWei, truncateHash, formatRelativeTime } from "@/lib/utils";
import { CopyButton } from "./copy-button";
import { ArrowDownLeft, ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Transaction } from "@/types";

interface TransactionRowProps {
  tx: Transaction;
  showPrLink?: boolean;
}

const incomingTypes = new Set([
  "SPONSORSHIP_IN", "AUDIT_FEE_IN", "STAKE_PENALTY_IN", "audit_fee_usdc",
]);

export function TransactionRow({ tx, showPrLink }: TransactionRowProps) {
  const isIncoming = incomingTypes.has(tx.tx_type);

  return (
    <div className="flex items-center justify-between gap-3 px-3 py-2 rounded-md hover:bg-muted/50 transition-colors">
      <div className="flex items-center gap-3 min-w-0">
        <div
          className={cn(
            "flex h-7 w-7 items-center justify-center rounded-full shrink-0",
            isIncoming ? "bg-approve/15" : "bg-reject/15",
          )}
        >
          {isIncoming ? (
            <ArrowDownLeft className="h-3.5 w-3.5 text-approve" />
          ) : (
            <ArrowUpRight className="h-3.5 w-3.5 text-reject" />
          )}
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-[10px] px-1.5 py-0">
              {tx.tx_type.replace(/_/g, " ")}
            </Badge>
            {showPrLink && tx.pr_id && (
              <span className="text-xs text-muted-foreground truncate">
                {tx.pr_id}
              </span>
            )}
          </div>
          {tx.tx_hash && (
            <div className="flex items-center gap-1 mt-0.5">
              <span className="font-mono text-xs text-muted-foreground">
                {truncateHash(tx.tx_hash)}
              </span>
              <CopyButton value={tx.tx_hash} />
            </div>
          )}
        </div>
      </div>

      <div className="flex flex-col items-end shrink-0">
        <span
          className={cn(
            "font-mono text-sm font-medium",
            isIncoming ? "text-approve" : "text-foreground",
          )}
        >
          {isIncoming ? "+" : "-"}
          {tx.currency === "ETH" ? formatWei(tx.amount_wei) : `${tx.amount_wei} ${tx.currency}`}
        </span>
        <span className="text-xs text-muted-foreground">
          {formatRelativeTime(tx.timestamp)}
        </span>
      </div>
    </div>
  );
}
