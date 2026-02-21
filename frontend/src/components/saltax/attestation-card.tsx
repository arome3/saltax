import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "./copy-button";
import { truncateHash } from "@/lib/utils";
import { Fingerprint, ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";
import { cn } from "@/lib/utils";
import type { AttestationProof } from "@/types";

interface AttestationCardProps {
  proof: AttestationProof & { signature_status?: string };
  compact?: boolean;
}

const sigStatusConfig: Record<string, { icon: typeof ShieldCheck; className: string; label: string }> = {
  valid: { icon: ShieldCheck, className: "text-approve", label: "Valid" },
  invalid: { icon: ShieldAlert, className: "text-reject", label: "Invalid" },
  unsigned: { icon: ShieldQuestion, className: "text-pending", label: "Unsigned" },
  unverifiable: { icon: ShieldQuestion, className: "text-muted-foreground", label: "Unverifiable" },
};

function Field({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value) return null;
  return (
    <div className="flex items-center justify-between gap-2 text-xs">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <div className="flex items-center gap-1 min-w-0">
        <span className="font-mono truncate">{truncateHash(value, 8)}</span>
        <CopyButton value={value} />
      </div>
    </div>
  );
}

export function AttestationCard({ proof, compact }: AttestationCardProps) {
  const sigStatus = proof.signature_status ?? "unsigned";
  const config = sigStatusConfig[sigStatus] ?? sigStatusConfig.unsigned;
  const SigIcon = config.icon;

  if (compact) {
    return (
      <div className="inline-flex items-center gap-1.5">
        <Fingerprint className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="font-mono text-xs">{truncateHash(proof.attestation_id, 6)}</span>
        <SigIcon className={cn("h-3.5 w-3.5", config.className)} aria-label={config.label} />
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <Fingerprint className="h-4 w-4" />
            Attestation Proof
          </CardTitle>
          <Badge variant="outline" className={cn("gap-1", config.className)}>
            <SigIcon className="h-3 w-3" />
            {config.label}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        <Field label="Attestation ID" value={proof.attestation_id} />
        <Field label="Input Hash" value={proof.pipeline_input_hash} />
        <Field label="Output Hash" value={proof.pipeline_output_hash} />
        <Field label="Docker Image" value={proof.docker_image_digest} />
        <Field label="TEE Platform" value={proof.tee_platform_id} />
        <Field label="Signer" value={proof.signer_address} />
        <Field label="Signature" value={proof.signature} />
        <Field label="Previous" value={proof.previous_attestation_id} />
        <Field label="AI Seed" value={proof.ai_seed?.toString()} />
        <Field label="AI Output Hash" value={proof.ai_output_hash} />
      </CardContent>
    </Card>
  );
}
