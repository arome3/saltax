import { cn } from "@/lib/utils";

interface ScoreBarProps {
  score: number;
  threshold?: number;
  label?: string;
  selfMod?: boolean;
}

export function ScoreBar({ score, threshold, label, selfMod }: ScoreBarProps) {
  const pct = Math.min(Math.max(score * 100, 0), 100);
  const thresholdPct = threshold ? threshold * 100 : null;
  const passed = threshold ? score >= threshold : true;

  return (
    <div className="space-y-1">
      {label && (
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">{label}</span>
          <span className={cn("font-mono font-medium", selfMod && "text-selfmod")}>
            {score.toFixed(2)}
          </span>
        </div>
      )}
      <div className="relative h-2 w-full rounded-full bg-muted overflow-hidden">
        <div
          className={cn(
            "absolute inset-y-0 left-0 rounded-full transition-all duration-500",
            selfMod
              ? "bg-selfmod"
              : passed
                ? "bg-approve"
                : "bg-reject",
          )}
          style={{ width: `${pct}%` }}
          role="progressbar"
          aria-valuenow={score}
          aria-valuemin={0}
          aria-valuemax={1}
          aria-label={label ? `${label}: ${score.toFixed(2)}` : undefined}
        />
        {thresholdPct !== null && (
          <div
            className="absolute inset-y-0 w-0.5 border-l-2 border-dashed border-foreground/40"
            style={{ left: `${thresholdPct}%` }}
            aria-hidden="true"
          />
        )}
      </div>
    </div>
  );
}
