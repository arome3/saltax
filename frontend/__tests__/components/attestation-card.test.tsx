import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { AttestationCard } from "@/components/saltax/attestation-card";
import type { AttestationProof } from "@/types";

const mockProof: AttestationProof & { signature_status?: string } = {
  attestation_id: "att_abc1234567890def",
  docker_image_digest: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  tee_platform_id: "tee_platform_xyz123456",
  pipeline_input_hash: "0xinput_hash_1234567890abcdef",
  pipeline_output_hash: "0xoutput_hash_1234567890abcdef",
  ai_seed: "12345",
  ai_output_hash: "0xai_output_hash_abcdef1234567890",
  ai_system_fingerprint: null,
  signature: "0xsig_abcdef1234567890abcdef1234567890",
  signer_address: "0xSignerAddr1234567890abcdef1234",
  created_at: "2025-01-01T00:00:00Z",
  previous_attestation_id: "att_prev_1234567890",
  signature_status: "valid",
};

describe("AttestationCard", () => {
  it("renders full card with 'Attestation Proof' title", () => {
    render(<AttestationCard proof={mockProof} />);
    expect(screen.getByText("Attestation Proof")).toBeInTheDocument();
  });

  it("renders field labels in full mode", () => {
    render(<AttestationCard proof={mockProof} />);
    expect(screen.getByText("Attestation ID")).toBeInTheDocument();
    expect(screen.getByText("Input Hash")).toBeInTheDocument();
    expect(screen.getByText("Output Hash")).toBeInTheDocument();
    expect(screen.getByText("Docker Image")).toBeInTheDocument();
    expect(screen.getByText("TEE Platform")).toBeInTheDocument();
    expect(screen.getByText("Signer")).toBeInTheDocument();
    expect(screen.getByText("Signature")).toBeInTheDocument();
  });

  it("renders signature status badge showing 'Valid'", () => {
    render(<AttestationCard proof={mockProof} />);
    expect(screen.getByText("Valid")).toBeInTheDocument();
  });

  it("renders compact mode with truncated attestation ID", () => {
    render(<AttestationCard proof={mockProof} compact />);
    // Should NOT show "Attestation Proof" title in compact mode
    expect(screen.queryByText("Attestation Proof")).toBeNull();
    // Should show truncated attestation_id text
    expect(screen.getByText(/att_ab.*def/)).toBeInTheDocument();
  });

  it("defaults signature_status to 'unsigned' when not provided", () => {
    const proofWithoutStatus = { ...mockProof };
    delete proofWithoutStatus.signature_status;
    render(<AttestationCard proof={proofWithoutStatus} />);
    expect(screen.getByText("Unsigned")).toBeInTheDocument();
  });

  it("omits fields with null values", () => {
    const proofWithNulls: AttestationProof & { signature_status?: string } = {
      ...mockProof,
      ai_seed: null,
      ai_output_hash: null,
      previous_attestation_id: null,
    };
    render(<AttestationCard proof={proofWithNulls} />);
    expect(screen.queryByText("AI Seed")).toBeNull();
    expect(screen.queryByText("AI Output Hash")).toBeNull();
    expect(screen.queryByText("Previous")).toBeNull();
  });
});
