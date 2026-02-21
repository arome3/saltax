import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { CountdownTimer } from "@/components/saltax/countdown-timer";

describe("CountdownTimer", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows formatted countdown for a future time", () => {
    const futureDate = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(); // +2h
    render(<CountdownTimer closesAt={futureDate} />);
    // Should show hours and minutes format, e.g. "1h 59m"
    expect(screen.getByText(/\d+h \d+m/)).toBeInTheDocument();
  });

  it("shows 'Expired' when closesAt is in the past", () => {
    const pastDate = new Date(Date.now() - 60_000).toISOString();
    render(<CountdownTimer closesAt={pastDate} />);
    expect(screen.getByText("Expired")).toBeInTheDocument();
  });

  it("calls onExpire when the timer reaches zero", () => {
    const onExpire = vi.fn();
    // Set closesAt to 2 seconds from now
    const closesAt = new Date(Date.now() + 2000).toISOString();
    render(<CountdownTimer closesAt={closesAt} onExpire={onExpire} />);

    expect(onExpire).not.toHaveBeenCalled();

    // Advance past the expiry
    act(() => {
      vi.advanceTimersByTime(3000);
    });

    expect(onExpire).toHaveBeenCalledTimes(1);
  });

  it("counts down as time passes", () => {
    // 90 seconds from now
    const closesAt = new Date(Date.now() + 90_000).toISOString();
    render(<CountdownTimer closesAt={closesAt} />);

    // Initially should show "1m 30s" or "1m 29s" depending on timing
    expect(screen.getByText(/1m \d+s/)).toBeInTheDocument();

    // Advance 60 seconds
    act(() => {
      vi.advanceTimersByTime(60_000);
    });

    // Should now show ~30s
    expect(screen.getByText(/\d+s/)).toBeInTheDocument();
  });

  it("has an aria-label describing the remaining time", () => {
    const futureDate = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    render(<CountdownTimer closesAt={futureDate} />);
    const timer = screen.getByLabelText(/Time remaining:/);
    expect(timer).toBeInTheDocument();
  });
});
