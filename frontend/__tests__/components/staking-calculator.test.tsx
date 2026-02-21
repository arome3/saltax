import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StakingCalculator } from "@/components/saltax/staking-calculator";

describe("StakingCalculator", () => {
  it("renders with default stake value of 0.05", () => {
    render(<StakingCalculator />);
    const input = screen.getByLabelText("Stake Amount (ETH)");
    expect(input).toHaveValue(0.05);
  });

  it("shows 4 outcome scenarios", () => {
    render(<StakingCalculator />);
    expect(screen.getByText("Approved, no challenge")).toBeInTheDocument();
    expect(screen.getByText("Approved, challenge rejected")).toBeInTheDocument();
    expect(screen.getByText("Approved, challenge upheld")).toBeInTheDocument();
    expect(screen.getByText("Rejected (full refund)")).toBeInTheDocument();
  });

  it("calculates correct ETH amounts for default stake", () => {
    render(<StakingCalculator />);
    // 0.05 * 1.10 = 0.0550
    expect(screen.getByText(/0\.0550 ETH/)).toBeInTheDocument();
    // 0.05 * 1.20 = 0.0600
    expect(screen.getByText(/0\.0600 ETH/)).toBeInTheDocument();
    // 0.05 * 0.50 = 0.0250
    expect(screen.getByText(/0\.0250 ETH/)).toBeInTheDocument();
    // 0.05 * 1.00 = 0.0500
    expect(screen.getByText(/0\.0500 ETH/)).toBeInTheDocument();
  });

  it("updates scenarios when stake amount is changed via input", async () => {
    const user = userEvent.setup();
    render(<StakingCalculator />);
    const input = screen.getByLabelText("Stake Amount (ETH)");

    await user.clear(input);
    await user.type(input, "1");

    // 1 * 1.10 = 1.1000
    expect(screen.getByText(/1\.1000 ETH/)).toBeInTheDocument();
    // 1 * 1.20 = 1.2000
    expect(screen.getByText(/1\.2000 ETH/)).toBeInTheDocument();
  });

  it("renders bounty tier buttons", () => {
    render(<StakingCalculator />);
    expect(screen.getByText(/bounty-xs: 0\.01 ETH/)).toBeInTheDocument();
    expect(screen.getByText(/bounty-sm: 0\.05 ETH/)).toBeInTheDocument();
    expect(screen.getByText(/bounty-md: 0\.1 ETH/)).toBeInTheDocument();
    expect(screen.getByText(/bounty-lg: 0\.25 ETH/)).toBeInTheDocument();
    expect(screen.getByText(/bounty-xl: 0\.5 ETH/)).toBeInTheDocument();
  });

  it("sets stake amount when a bounty tier button is clicked", async () => {
    const user = userEvent.setup();
    render(<StakingCalculator />);

    await user.click(screen.getByText(/bounty-lg: 0\.25 ETH/));

    const input = screen.getByLabelText("Stake Amount (ETH)");
    expect(input).toHaveValue(0.25);

    // 0.25 * 1.10 = 0.2750
    expect(screen.getByText(/0\.2750 ETH/)).toBeInTheDocument();
  });
});
