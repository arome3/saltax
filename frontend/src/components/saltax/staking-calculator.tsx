"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

const bountyLabels: Record<string, number> = {
  "bounty-xs": 0.01,
  "bounty-sm": 0.05,
  "bounty-md": 0.10,
  "bounty-lg": 0.25,
  "bounty-xl": 0.50,
};

const scenarios = [
  { label: "Approved, no challenge", rate: 1.10, color: "text-approve" },
  { label: "Approved, challenge rejected", rate: 1.20, color: "text-approve" },
  { label: "Approved, challenge upheld", rate: 0.50, color: "text-reject" },
  { label: "Rejected (full refund)", rate: 1.00, color: "text-foreground" },
];

export function StakingCalculator() {
  const [stakeEth, setStakeEth] = useState("0.05");
  const stake = parseFloat(stakeEth) || 0;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm">Staking Calculator</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="stake-input" className="text-xs">
            Stake Amount (ETH)
          </Label>
          <Input
            id="stake-input"
            type="number"
            step="0.01"
            min="0"
            value={stakeEth}
            onChange={(e) => setStakeEth(e.target.value)}
            className="font-mono h-9"
          />
        </div>

        <div className="space-y-2">
          <span className="text-xs font-medium text-muted-foreground">
            Bounty Tiers
          </span>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(bountyLabels).map(([label, eth]) => (
              <button
                key={label}
                type="button"
                onClick={() => setStakeEth(eth.toString())}
                className={cn(
                  "rounded-md border px-2 py-1 text-xs font-mono transition-colors",
                  "hover:bg-accent hover:text-accent-foreground",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  parseFloat(stakeEth) === eth && "bg-accent text-accent-foreground",
                )}
              >
                {label}: {eth} ETH
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-1.5 pt-2 border-t">
          <span className="text-xs font-medium text-muted-foreground">
            Outcome Scenarios
          </span>
          {scenarios.map((s) => (
            <div
              key={s.label}
              className="flex items-center justify-between text-xs"
            >
              <span className="text-muted-foreground">{s.label}</span>
              <span className={cn("font-mono font-medium", s.color)}>
                {(stake * s.rate).toFixed(4)} ETH
                <span className="text-muted-foreground ml-1">
                  ({s.rate >= 1 ? "+" : ""}
                  {((s.rate - 1) * 100).toFixed(0)}%)
                </span>
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
