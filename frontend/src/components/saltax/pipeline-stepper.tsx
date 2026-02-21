import { cn } from "@/lib/utils";
import { Check, Loader2, Circle } from "lucide-react";

export interface PipelineStage {
  label: string;
  status: "completed" | "active" | "pending" | "failed";
}

interface PipelineStepperProps {
  stages: PipelineStage[];
}

export function PipelineStepper({ stages }: PipelineStepperProps) {
  return (
    <div className="flex items-center gap-1" role="list" aria-label="Pipeline stages">
      {stages.map((stage, i) => (
        <div key={stage.label} className="flex items-center" role="listitem">
          <div className="flex flex-col items-center gap-1">
            <div
              className={cn(
                "flex h-7 w-7 items-center justify-center rounded-full border-2 transition-colors",
                stage.status === "completed" && "border-approve bg-approve/15",
                stage.status === "active" && "border-info bg-info/15",
                stage.status === "failed" && "border-reject bg-reject/15",
                stage.status === "pending" && "border-muted-foreground/30",
              )}
            >
              {stage.status === "completed" && (
                <Check className="h-3.5 w-3.5 text-approve" />
              )}
              {stage.status === "active" && (
                <Loader2 className="h-3.5 w-3.5 text-info animate-spin" />
              )}
              {stage.status === "failed" && (
                <Circle className="h-3.5 w-3.5 text-reject" />
              )}
              {stage.status === "pending" && (
                <Circle className="h-3.5 w-3.5 text-muted-foreground/30" />
              )}
            </div>
            <span
              className={cn(
                "text-[10px] font-medium leading-none",
                stage.status === "completed" && "text-approve",
                stage.status === "active" && "text-info",
                stage.status === "failed" && "text-reject",
                stage.status === "pending" && "text-muted-foreground/50",
              )}
            >
              {stage.label}
            </span>
          </div>
          {i < stages.length - 1 && (
            <div
              className={cn(
                "h-0.5 w-8 mx-1 mt-[-14px]",
                stage.status === "completed" ? "bg-approve/50" : "bg-border",
              )}
              aria-hidden="true"
            />
          )}
        </div>
      ))}
    </div>
  );
}
