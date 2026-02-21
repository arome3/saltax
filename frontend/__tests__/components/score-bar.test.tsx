import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScoreBar } from "@/components/saltax/score-bar";

describe("ScoreBar", () => {
  it("has role='progressbar' with aria-valuenow set to the score", () => {
    render(<ScoreBar score={0.75} />);
    const bar = screen.getByRole("progressbar");
    expect(bar).toHaveAttribute("aria-valuenow", "0.75");
    expect(bar).toHaveAttribute("aria-valuemin", "0");
    expect(bar).toHaveAttribute("aria-valuemax", "1");
  });

  it("displays the label and formatted score", () => {
    render(<ScoreBar score={0.832} label="Security" />);
    expect(screen.getByText("Security")).toBeInTheDocument();
    expect(screen.getByText("0.83")).toBeInTheDocument();
  });

  it("sets the progress bar width based on score percentage", () => {
    render(<ScoreBar score={0.6} />);
    const bar = screen.getByRole("progressbar");
    expect(bar).toHaveStyle({ width: "60%" });
  });

  it("clamps the bar width between 0% and 100%", () => {
    const { unmount } = render(<ScoreBar score={1.5} />);
    expect(screen.getByRole("progressbar")).toHaveStyle({ width: "100%" });
    unmount();

    render(<ScoreBar score={-0.2} />);
    expect(screen.getByRole("progressbar")).toHaveStyle({ width: "0%" });
  });

  it("renders the threshold dashed line when threshold is provided", () => {
    const { container } = render(<ScoreBar score={0.8} threshold={0.7} />);
    const thresholdLine = container.querySelector(".border-dashed");
    expect(thresholdLine).toBeInTheDocument();
    expect(thresholdLine).toHaveStyle({ left: "70%" });
  });

  it("does not render threshold line when threshold is not provided", () => {
    const { container } = render(<ScoreBar score={0.5} />);
    const thresholdLine = container.querySelector(".border-dashed");
    expect(thresholdLine).toBeNull();
  });
});
