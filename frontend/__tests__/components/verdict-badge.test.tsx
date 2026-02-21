import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { VerdictBadge } from "@/components/saltax/verdict-badge";

describe("VerdictBadge", () => {
  it("renders 'Approved' label for APPROVE verdict", () => {
    render(<VerdictBadge verdict="APPROVE" />);
    expect(screen.getByText("Approved")).toBeInTheDocument();
  });

  it("renders 'Rejected' label for REJECT verdict", () => {
    render(<VerdictBadge verdict="REJECT" />);
    expect(screen.getByText("Rejected")).toBeInTheDocument();
  });

  it("renders 'Changes' label for REQUEST_CHANGES verdict", () => {
    render(<VerdictBadge verdict="REQUEST_CHANGES" />);
    expect(screen.getByText("Changes")).toBeInTheDocument();
  });

  it("renders 'Unknown' label for UNKNOWN verdict", () => {
    render(<VerdictBadge verdict="UNKNOWN" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });

  it("renders an icon with aria-hidden", () => {
    const { container } = render(<VerdictBadge verdict="APPROVE" />);
    const icon = container.querySelector("[aria-hidden='true']");
    expect(icon).toBeInTheDocument();
  });

  it("applies size-specific classes for each size variant", () => {
    const { rerender, container } = render(
      <VerdictBadge verdict="APPROVE" size="sm" />,
    );
    const badgeSm = container.firstElementChild!;
    expect(badgeSm.className).toContain("text-xs");

    rerender(<VerdictBadge verdict="APPROVE" size="lg" />);
    const badgeLg = container.firstElementChild!;
    expect(badgeLg.className).toContain("text-sm");
  });
});
