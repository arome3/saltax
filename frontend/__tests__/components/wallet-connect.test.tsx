import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const mockConnect = vi.fn();
const mockDisconnect = vi.fn();
const mockConnectors: unknown[] = [];

vi.mock("wagmi", () => ({
  useAccount: vi.fn(() => ({ address: undefined, isConnected: false })),
  useConnect: vi.fn(() => ({ connect: mockConnect, connectors: mockConnectors })),
  useDisconnect: vi.fn(() => ({ disconnect: mockDisconnect })),
}));

import { WalletConnect } from "@/components/saltax/wallet-connect";
import { useConnect } from "wagmi";

describe("WalletConnect", () => {
  it("shows 'Connect Wallet' button when disconnected", () => {
    render(<WalletConnect />);
    expect(
      screen.getByRole("button", { name: /connect wallet/i }),
    ).toBeInTheDocument();
  });

  it("shows 'Connect' button text in compact mode when disconnected", () => {
    render(<WalletConnect compact />);
    expect(
      screen.getByRole("button", { name: /connect/i }),
    ).toBeInTheDocument();
  });

  it("calls connect with the first connector on click", async () => {
    const localConnect = vi.fn();
    const connector = { id: "injected", name: "MetaMask" };
    vi.mocked(useConnect).mockReturnValue({
      connect: localConnect,
      connectors: [connector],
    } as unknown as ReturnType<typeof useConnect>);

    const user = userEvent.setup();
    render(<WalletConnect />);

    await user.click(screen.getByRole("button", { name: /connect wallet/i }));

    expect(localConnect).toHaveBeenCalledWith({ connector });
  });

  it("does not call connect when there are no connectors", async () => {
    const localConnect = vi.fn();
    vi.mocked(useConnect).mockReturnValue({
      connect: localConnect,
      connectors: [],
    } as unknown as ReturnType<typeof useConnect>);

    const user = userEvent.setup();
    render(<WalletConnect />);

    await user.click(screen.getByRole("button", { name: /connect wallet/i }));

    expect(localConnect).not.toHaveBeenCalled();
  });
});
