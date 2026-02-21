"use client";

import { useCallback, useState } from "react";
import { useSubmitAudit } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import {
  Shield,
  Sparkles,
  ScanLine,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  DollarSign,
} from "lucide-react";
import type { AuditScope } from "@/types";

// ── Scope options ───────────────────────────────────────────────────────────

const SCOPE_OPTIONS: {
  value: AuditScope;
  label: string;
  description: string;
  price: number;
  icon: typeof Shield;
}[] = [
  {
    value: "security_only",
    label: "Security Only",
    description: "Vulnerability scanning, dependency audit, secret detection",
    price: 5,
    icon: Shield,
  },
  {
    value: "quality_only",
    label: "Quality Only",
    description: "Code quality, test coverage, maintainability analysis",
    price: 3,
    icon: Sparkles,
  },
  {
    value: "full",
    label: "Full Audit",
    description: "Complete security + quality + performance analysis",
    price: 10,
    icon: ScanLine,
  },
];

// ── URL validation ──────────────────────────────────────────────────────────

function isValidGitHubUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      (parsed.hostname === "github.com" || parsed.hostname === "www.github.com") &&
      parsed.pathname.split("/").filter(Boolean).length >= 2
    );
  } catch {
    return false;
  }
}

// ── Success state ───────────────────────────────────────────────────────────

function SuccessState({ auditId, onReset }: { auditId: string; onReset: () => void }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-4 py-16">
        <div className="rounded-full bg-approve/10 p-4">
          <CheckCircle2 className="h-8 w-8 text-approve" />
        </div>
        <div className="text-center max-w-sm">
          <h2 className="text-lg font-semibold">Audit Submitted</h2>
          <p className="text-sm text-muted-foreground mt-2">
            Your audit request has been queued. Results will be delivered
            to the repository.
          </p>
          <p className="font-mono text-xs text-muted-foreground mt-3">
            Audit ID: {auditId}
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={onReset}>
          Submit Another
        </Button>
      </CardContent>
    </Card>
  );
}

// ── Error state ─────────────────────────────────────────────────────────────

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="rounded-md border border-reject/30 bg-reject/5 p-3 flex items-start gap-2">
      <AlertTriangle className="h-4 w-4 text-reject shrink-0 mt-0.5" />
      <div>
        <p className="text-sm font-medium text-reject">Submission Failed</p>
        <p className="text-xs text-muted-foreground mt-0.5">{message}</p>
      </div>
    </div>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function PaidAuditPage() {
  const [repoUrl, setRepoUrl] = useState("");
  const [commitSha, setCommitSha] = useState("");
  const [scope, setScope] = useState<AuditScope>("full");
  const [touched, setTouched] = useState(false);

  const submitAudit = useSubmitAudit();

  const urlValid = isValidGitHubUrl(repoUrl);
  const showUrlError = touched && repoUrl.length > 0 && !urlValid;
  const selectedScope = SCOPE_OPTIONS.find((s) => s.value === scope);

  const canSubmit = urlValid && commitSha.trim().length > 0 && !submitAudit.isPending;

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      setTouched(true);
      if (!canSubmit) return;

      submitAudit.mutate({
        repository_url: repoUrl.trim(),
        commit_sha: commitSha.trim(),
        scope,
      });
    },
    [repoUrl, commitSha, scope, canSubmit, submitAudit],
  );

  const handleReset = useCallback(() => {
    setRepoUrl("");
    setCommitSha("");
    setScope("full");
    setTouched(false);
    submitAudit.reset();
  }, [submitAudit]);

  // Show success screen after successful submission
  if (submitAudit.isSuccess && submitAudit.data) {
    return (
      <SuccessState
        auditId={submitAudit.data.audit_id}
        onReset={handleReset}
      />
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* ── Error banner ─────────────────────────────────────────────── */}
        {submitAudit.isError && (
          <ErrorBanner
            message={
              submitAudit.error instanceof Error
                ? submitAudit.error.message
                : "An unexpected error occurred. Please try again."
            }
          />
        )}

        {/* ── Repository URL ──────────────────────────────────────────── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Repository</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="repo-url" className="text-xs">
                GitHub Repository URL
              </Label>
              <Input
                id="repo-url"
                type="url"
                placeholder="https://github.com/owner/repo"
                value={repoUrl}
                onChange={(e) => {
                  setRepoUrl(e.target.value);
                  if (!touched) setTouched(true);
                }}
                className={cn(
                  showUrlError && "border-reject focus-visible:ring-reject",
                )}
              />
              {showUrlError && (
                <p className="text-xs text-reject">
                  Enter a valid GitHub repository URL
                </p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="commit-sha" className="text-xs">
                Commit SHA
              </Label>
              <Input
                id="commit-sha"
                placeholder="e.g. abc123def456..."
                value={commitSha}
                onChange={(e) => setCommitSha(e.target.value)}
                className="font-mono"
              />
              <p className="text-[10px] text-muted-foreground">
                The specific commit to audit. Use HEAD for the latest.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* ── Scope selector ──────────────────────────────────────────── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Audit Scope</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-3">
              {SCOPE_OPTIONS.map((option) => {
                const Icon = option.icon;
                const isSelected = scope === option.value;
                return (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => setScope(option.value)}
                    className={cn(
                      "rounded-lg border p-4 text-left transition-colors",
                      "hover:bg-accent/50",
                      "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                      isSelected && "bg-accent border-primary/40 ring-1 ring-primary/20",
                    )}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <Icon
                        className={cn(
                          "h-4 w-4",
                          isSelected ? "text-primary" : "text-muted-foreground",
                        )}
                      />
                      <span className="text-sm font-medium">{option.label}</span>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {option.description}
                    </p>
                    <p className="mt-2 font-mono text-lg font-bold">
                      ${option.price}
                    </p>
                  </button>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* ── Payment summary ─────────────────────────────────────────── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <DollarSign className="h-4 w-4" />
              Payment Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Scope</span>
                <span className="font-medium">
                  {selectedScope?.label ?? "--"}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Repository</span>
                <span className="font-mono text-xs truncate max-w-[200px]">
                  {repoUrl || "--"}
                </span>
              </div>
              <div className="border-t pt-2 flex items-center justify-between">
                <span className="text-sm font-medium">Total</span>
                <span className="text-xl font-bold font-mono">
                  ${selectedScope?.price ?? 0}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* ── Submit button ───────────────────────────────────────────── */}
        <Button
          type="submit"
          size="lg"
          disabled={!canSubmit}
          className="w-full"
        >
          {submitAudit.isPending ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Submitting...
            </>
          ) : (
            <>
              <ScanLine className="h-4 w-4" />
              Submit Audit Request - ${selectedScope?.price ?? 0}
            </>
          )}
        </Button>
      </form>
    </div>
  );
}
