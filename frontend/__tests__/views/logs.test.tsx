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
import { screen } from "@testing-library/react";
import { renderWithProviders } from "../helpers/render";
import SystemLogsPage from "@/app/logs/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/logs",
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

describe("SystemLogsPage", () => {
  it("renders the level filter pills", () => {
    renderWithProviders(<SystemLogsPage />);

    expect(screen.getByText("All")).toBeInTheDocument();
    expect(screen.getByText("Info")).toBeInTheDocument();
    expect(screen.getByText("Warning")).toBeInTheDocument();
    expect(screen.getByText("Error")).toBeInTheDocument();
  });

  it("renders the search input", () => {
    renderWithProviders(<SystemLogsPage />);

    expect(
      screen.getByPlaceholderText("Search logs..."),
    ).toBeInTheDocument();
  });

  it("shows empty logs state when no events are present", () => {
    renderWithProviders(<SystemLogsPage />);

    expect(screen.getByText("No log events yet")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Logs will stream in real-time as the agent operates",
      ),
    ).toBeInTheDocument();
  });

  it("shows Disconnected status and Pause button", () => {
    renderWithProviders(<SystemLogsPage />);

    expect(screen.getByText("Disconnected")).toBeInTheDocument();
    expect(screen.getByText("Pause")).toBeInTheDocument();
    expect(screen.getByText("Clear")).toBeInTheDocument();
  });
});
