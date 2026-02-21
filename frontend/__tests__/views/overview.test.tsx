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
import OverviewDashboard from "@/app/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

vi.mock("@/lib/websocket", () => ({
  useWebSocket: () => ({
    events: [],
    connected: false,
    paused: false,
    setPaused: vi.fn(),
    clearEvents: vi.fn(),
  }),
}));

describe("OverviewDashboard", () => {
  it("renders metric cards with data from the API", async () => {
    renderWithProviders(<OverviewDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Total PRs")).toBeInTheDocument();
    });

    expect(screen.getByText("150")).toBeInTheDocument();
    expect(screen.getByText("87.0%")).toBeInTheDocument();
    expect(screen.getByText("Patterns")).toBeInTheDocument();
    expect(screen.getByText("450")).toBeInTheDocument();
    expect(screen.getByText("Vulns Caught")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
  });

  it("shows the agent name and status info in the hero section", async () => {
    renderWithProviders(<OverviewDashboard />);

    await waitFor(() => {
      expect(screen.getByText("SaltaX")).toBeInTheDocument();
    });

    expect(screen.getByText("v1.0.0")).toBeInTheDocument();
  });

  it("shows the Live Activity section with waiting message when no events", async () => {
    renderWithProviders(<OverviewDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Live Activity")).toBeInTheDocument();
    });

    expect(
      screen.getByText("Waiting for activity..."),
    ).toBeInTheDocument();
  });

  it("shows Disconnected label when websocket is not connected", async () => {
    renderWithProviders(<OverviewDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Disconnected")).toBeInTheDocument();
    });
  });
});
