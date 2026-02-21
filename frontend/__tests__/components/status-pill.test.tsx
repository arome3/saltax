import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusPill } from "@/components/saltax/status-pill";

describe("StatusPill", () => {
  it("has role='status'", () => {
    render(<StatusPill status="operational" />);
    expect(screen.getByRole("status")).toBeInTheDocument();
  });

  it("displays 'Operational' label for operational status", () => {
    render(<StatusPill status="operational" />);
    expect(screen.getByText("Operational")).toBeInTheDocument();
  });

  it("displays 'Degraded' label for degraded status", () => {
    render(<StatusPill status="degraded" />);
    expect(screen.getByText("Degraded")).toBeInTheDocument();
  });

  it("displays 'Halted' label for halted status", () => {
    render(<StatusPill status="halted" />);
    expect(screen.getByText("Halted")).toBeInTheDocument();
  });

  it("displays 'Unknown' label for unknown status", () => {
    render(<StatusPill status="unknown" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });

  it("sets the correct aria-label based on status", () => {
    render(<StatusPill status="degraded" />);
    expect(
      screen.getByLabelText("Agent status: Degraded"),
    ).toBeInTheDocument();
  });
});
