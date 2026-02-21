import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MetricCard } from "@/components/saltax/metric-card";

describe("MetricCard", () => {
  it("renders the label and value", () => {
    render(<MetricCard label="Total PRs" value={42} />);
    expect(screen.getByText("Total PRs")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("renders a string value", () => {
    render(<MetricCard label="Balance" value="1.5 ETH" />);
    expect(screen.getByText("1.5 ETH")).toBeInTheDocument();
  });

  it("shows trend text when trend is provided", () => {
    render(
      <MetricCard label="Score" value={87} trend="+12%" trendDirection="up" />,
    );
    expect(screen.getByText("+12%")).toBeInTheDocument();
  });

  it("does not render trend when trend is not provided", () => {
    const { container } = render(<MetricCard label="Score" value={87} />);
    // The trend span should not exist
    expect(container.querySelector(".text-approve")).toBeNull();
    expect(container.querySelector(".text-reject")).toBeNull();
  });

  it("applies up direction style for upward trend", () => {
    render(
      <MetricCard label="Score" value={87} trend="+5%" trendDirection="up" />,
    );
    const trendEl = screen.getByText("+5%").closest("span");
    expect(trendEl?.className).toContain("text-approve");
  });

  it("applies down direction style for downward trend", () => {
    render(
      <MetricCard
        label="Score"
        value={87}
        trend="-3%"
        trendDirection="down"
      />,
    );
    const trendEl = screen.getByText("-3%").closest("span");
    expect(trendEl?.className).toContain("text-reject");
  });
});
