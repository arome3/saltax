import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { TransactionRow } from "@/components/saltax/transaction-row";
import type { Transaction } from "@/types";

function makeTx(overrides: Partial<Transaction> = {}): Transaction {
  return {
    id: "tx-1",
    tx_type: "AUDIT_FEE_IN",
    amount_wei: 1_000_000_000_000_000_000, // 1 ETH in wei
    currency: "ETH",
    counterparty: "0xSender1234567890",
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe("TransactionRow", () => {
  it("shows '+' prefix for incoming transaction types", () => {
    const incomingTypes = [
      "SPONSORSHIP_IN",
      "AUDIT_FEE_IN",
      "STAKE_PENALTY_IN",
      "audit_fee_usdc",
    ] as const;

    for (const tx_type of incomingTypes) {
      const { unmount } = render(
        <TransactionRow tx={makeTx({ tx_type })} />,
      );
      // The amount element should contain "+"
      const amountEl = screen.getByText(/^\+/);
      expect(amountEl).toBeInTheDocument();
      unmount();
    }
  });

  it("shows '-' prefix for outgoing transaction types", () => {
    render(
      <TransactionRow tx={makeTx({ tx_type: "BOUNTY_OUT" })} />,
    );
    const amountEl = screen.getByText(/^-/);
    expect(amountEl).toBeInTheDocument();
  });

  it("renders the tx_type as a badge with spaces instead of underscores", () => {
    render(
      <TransactionRow tx={makeTx({ tx_type: "AUDIT_FEE_IN" })} />,
    );
    expect(screen.getByText("AUDIT FEE IN")).toBeInTheDocument();
  });

  it("shows tx_hash when present", () => {
    render(
      <TransactionRow
        tx={makeTx({ tx_hash: "0xabcdef1234567890abcdef1234567890" })}
      />,
    );
    // Truncated hash should appear
    expect(screen.getByText(/0xabcdef.*567890/)).toBeInTheDocument();
  });

  it("does not show tx_hash section when hash is absent", () => {
    const { container } = render(
      <TransactionRow tx={makeTx({ tx_hash: undefined })} />,
    );
    // No copy button should be present for the hash
    expect(
      container.querySelector("[aria-label='Copy to clipboard']"),
    ).toBeNull();
  });

  it("shows pr_id when showPrLink is true and pr_id exists", () => {
    render(
      <TransactionRow
        tx={makeTx({ pr_id: "owner/repo#42" })}
        showPrLink
      />,
    );
    expect(screen.getByText("owner/repo#42")).toBeInTheDocument();
  });
});
