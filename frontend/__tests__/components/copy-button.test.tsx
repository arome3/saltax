import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act, fireEvent } from "@testing-library/react";
import { CopyButton } from "@/components/saltax/copy-button";

describe("CopyButton", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders with 'Copy to clipboard' aria-label by default", () => {
    render(<CopyButton value="abc123" />);
    expect(
      screen.getByRole("button", { name: "Copy to clipboard" }),
    ).toBeInTheDocument();
  });

  it("calls navigator.clipboard.writeText with the value on click", async () => {
    const writeTextSpy = vi
      .spyOn(navigator.clipboard, "writeText")
      .mockResolvedValue(undefined);
    render(<CopyButton value="test-hash-value" />);

    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Copy to clipboard" }),
      );
    });

    expect(writeTextSpy).toHaveBeenCalledWith("test-hash-value");
    writeTextSpy.mockRestore();
  });

  it("changes aria-label to 'Copied' after clicking", async () => {
    vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    render(<CopyButton value="val" />);

    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Copy to clipboard" }),
      );
    });

    expect(
      screen.getByRole("button", { name: "Copied" }),
    ).toBeInTheDocument();
  });

  it("reverts aria-label back to 'Copy to clipboard' after 2 seconds", async () => {
    vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    render(<CopyButton value="val" />);

    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Copy to clipboard" }),
      );
    });

    expect(
      screen.getByRole("button", { name: "Copied" }),
    ).toBeInTheDocument();

    // Advance 2 seconds
    act(() => {
      vi.advanceTimersByTime(2000);
    });

    expect(
      screen.getByRole("button", { name: "Copy to clipboard" }),
    ).toBeInTheDocument();
  });
});
