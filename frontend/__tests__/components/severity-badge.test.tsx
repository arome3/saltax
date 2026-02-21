import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeverityBadge } from "@/components/saltax/severity-badge";

describe("SeverityBadge", () => {
  it("renders the severity text for CRITICAL", () => {
    render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  });

  it("renders the severity text for each severity level", () => {
    const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
    for (const severity of severities) {
      const { unmount } = render(<SeverityBadge severity={severity} />);
      expect(screen.getByText(severity)).toBeInTheDocument();
      unmount();
    }
  });

  it("renders an icon with aria-hidden", () => {
    const { container } = render(<SeverityBadge severity="HIGH" />);
    const icon = container.querySelector("[aria-hidden='true']");
    expect(icon).toBeInTheDocument();
  });

  it("defaults to md size", () => {
    const { container } = render(<SeverityBadge severity="LOW" />);
    const badge = container.firstElementChild!;
    expect(badge.className).toContain("py-0.5");
  });

  it("applies sm size classes when size is sm", () => {
    const { container } = render(
      <SeverityBadge severity="LOW" size="sm" />,
    );
    const badge = container.firstElementChild!;
    expect(badge.className).toContain("py-0");
    expect(badge.className).toContain("px-1.5");
  });
});
