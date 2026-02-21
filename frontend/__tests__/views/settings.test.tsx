import { setupServer } from "msw/node";
import { handlers } from "../helpers/msw-handlers";
import {
  beforeAll,
  afterAll,
  afterEach,
  describe,
  it,
  expect,
  vi,
} from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../helpers/render";
import SettingsPage from "@/app/settings/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/settings",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

describe("SettingsPage", () => {
  it("renders the Agent Identity section after loading", async () => {
    renderWithProviders(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText("Agent Identity")).toBeInTheDocument();
    });
  });

  it("shows identity fields from the API data", async () => {
    renderWithProviders(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText("Wallet Address")).toBeInTheDocument();
    });

    expect(screen.getByText("ERC-8004 ID")).toBeInTheDocument();
    expect(screen.getByText("Agent ID")).toBeInTheDocument();
    expect(screen.getByText("SaltaX")).toBeInTheDocument();
  });

  it("shows local metrics including PRs reviewed count", async () => {
    renderWithProviders(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText("PRs Reviewed")).toBeInTheDocument();
    });

    expect(screen.getByText("150")).toBeInTheDocument();
    expect(screen.getByText("Vulns Caught")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
  });

  it("renders the Configuration section", async () => {
    renderWithProviders(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText("Configuration")).toBeInTheDocument();
    });

    // These render only after status data loads (behind isLoading guard)
    await waitFor(() => {
      expect(screen.getByText("Intelligence DB")).toBeInTheDocument();
    });

    expect(screen.getByText("Initialized")).toBeInTheDocument();
  });
});
