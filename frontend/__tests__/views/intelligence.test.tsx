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
import IntelligenceStatsPage from "@/app/intelligence/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/intelligence",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: any) => (
    <div data-testid="chart-container">{children}</div>
  ),
  AreaChart: () => <div data-testid="area-chart" />,
  Area: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
  PieChart: () => <div data-testid="pie-chart" />,
  Pie: () => null,
  Cell: () => null,
  BarChart: () => <div data-testid="bar-chart" />,
  Bar: () => null,
  Legend: () => null,
  LineChart: () => <div data-testid="line-chart" />,
  Line: () => null,
}));

describe("IntelligenceStatsPage", () => {
  it("renders metric cards with intelligence stats", async () => {
    renderWithProviders(<IntelligenceStatsPage />);

    await waitFor(() => {
      expect(screen.getByText("Total Patterns")).toBeInTheDocument();
    });

    expect(screen.getByText("450")).toBeInTheDocument();
    expect(screen.getByText("Avg FP Rate")).toBeInTheDocument();
    expect(screen.getByText("3.0%")).toBeInTheDocument();
  });

  it("shows pattern count for last 7 days", async () => {
    renderWithProviders(<IntelligenceStatsPage />);

    await waitFor(() => {
      expect(screen.getByText("Patterns (7d)")).toBeInTheDocument();
    });

    expect(screen.getByText("35")).toBeInTheDocument();
  });

  it("renders the Category Distribution chart section", async () => {
    renderWithProviders(<IntelligenceStatsPage />);

    await waitFor(() => {
      expect(
        screen.getByText("Category Distribution"),
      ).toBeInTheDocument();
    });
  });

  it("renders the Top Contributing Repos section with data", async () => {
    renderWithProviders(<IntelligenceStatsPage />);

    await waitFor(() => {
      expect(
        screen.getByText("Top Contributing Repos"),
      ).toBeInTheDocument();
    });

    expect(screen.getByText("owner/repo")).toBeInTheDocument();
    expect(screen.getByText("80")).toBeInTheDocument();
  });
});
