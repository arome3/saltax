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
import PipelineFeedPage from "@/app/pipeline/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/pipeline",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

describe("PipelineFeedPage", () => {
  it("renders the search and filter bar", async () => {
    renderWithProviders(<PipelineFeedPage />);

    await waitFor(() => {
      expect(
        screen.getByPlaceholderText("Filter by repository..."),
      ).toBeInTheDocument();
    });

    expect(screen.getByText("Search")).toBeInTheDocument();
  });

  it("shows the pipeline table with records after loading", async () => {
    renderWithProviders(<PipelineFeedPage />);

    await waitFor(() => {
      expect(screen.getByText("owner/repo#42")).toBeInTheDocument();
    });

    expect(screen.getByText("owner/repo")).toBeInTheDocument();
  });

  it("renders table column headers", async () => {
    renderWithProviders(<PipelineFeedPage />);

    await waitFor(() => {
      expect(screen.getByText("PR#")).toBeInTheDocument();
    });

    expect(screen.getByText("Repo")).toBeInTheDocument();
    expect(screen.getByText("Verdict")).toBeInTheDocument();
    expect(screen.getByText("Score")).toBeInTheDocument();
    expect(screen.getByText("Proof")).toBeInTheDocument();
  });

  it("shows keyboard navigation hints", async () => {
    renderWithProviders(<PipelineFeedPage />);

    await waitFor(() => {
      // Text is split across <kbd> elements, so use substring match
      expect(screen.getByText(/to navigate/)).toBeInTheDocument();
    });
  });
});
