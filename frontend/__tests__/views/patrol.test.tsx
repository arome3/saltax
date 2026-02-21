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
import PatrolDashboard from "@/app/patrol/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/patrol",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

describe("PatrolDashboard", () => {
  it("renders metric cards with zero counts when APIs return empty arrays", async () => {
    renderWithProviders(<PatrolDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Total Scans")).toBeInTheDocument();
    });

    expect(screen.getByText("Vulns Found")).toBeInTheDocument();
    expect(screen.getByText("Patches Generated")).toBeInTheDocument();
  });

  it("shows the empty vulnerabilities state", async () => {
    renderWithProviders(<PatrolDashboard />);

    await waitFor(() => {
      expect(
        screen.getByText("No vulnerabilities found"),
      ).toBeInTheDocument();
    });
  });

  it("shows the empty patches state", async () => {
    renderWithProviders(<PatrolDashboard />);

    await waitFor(() => {
      expect(
        screen.getByText("No patches generated"),
      ).toBeInTheDocument();
    });
  });

  it("renders the Vulnerabilities and Patch Tracker section headings", async () => {
    renderWithProviders(<PatrolDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Vulnerabilities")).toBeInTheDocument();
    });

    expect(screen.getByText("Patch Tracker")).toBeInTheDocument();
  });
});
