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
import TreasuryDashboard from "@/app/treasury/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/treasury",
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

describe("TreasuryDashboard", () => {
  it("shows the treasury balance after loading", async () => {
    renderWithProviders(<TreasuryDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Treasury Balance")).toBeInTheDocument();
    });
  });

  it("shows the Reserve and Bounty Pool labels", async () => {
    renderWithProviders(<TreasuryDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Reserve")).toBeInTheDocument();
    });

    expect(screen.getByText("Bounty Pool")).toBeInTheDocument();
    expect(screen.getByText("Available")).toBeInTheDocument();
  });

  it("renders the transactions section with data", async () => {
    renderWithProviders(<TreasuryDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Transactions")).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByText("1 total")).toBeInTheDocument();
    });
  });

  it("renders the budget allocation section", async () => {
    renderWithProviders(<TreasuryDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Budget Allocation")).toBeInTheDocument();
    });
  });
});
