import { Suspense } from "react";
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
import { screen, waitFor, act } from "@testing-library/react";
import { renderWithProviders } from "../helpers/render";
import PipelineDetailPage from "@/app/pipeline/[id]/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({ id: "pipe-001" }),
  usePathname: () => "/pipeline/pipe-001",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

/**
 * Wrap in Suspense + await act() because the component uses React 19's
 * use(params) which suspends until the promise resolves. Without awaiting
 * act, React never re-renders past the Suspense fallback.
 */
async function renderDetail() {
  const params = Promise.resolve({ id: "pipe-001" });
  await act(async () => {
    renderWithProviders(
      <Suspense fallback={<div>Loading...</div>}>
        <PipelineDetailPage params={params} />
      </Suspense>,
    );
  });
}

describe("PipelineDetailPage", () => {
  it("shows the PR ID and verdict badge after loading", async () => {
    await renderDetail();

    await waitFor(() => {
      expect(screen.getByText("owner/repo#42")).toBeInTheDocument();
    });

    expect(screen.getByText("Composite Score")).toBeInTheDocument();
  });

  it("displays the composite score value", async () => {
    await renderDetail();

    await waitFor(() => {
      expect(screen.getByText("0.870")).toBeInTheDocument();
    });
  });

  it("renders the score breakdown section", async () => {
    await renderDetail();

    await waitFor(() => {
      expect(screen.getByText("Score Breakdown")).toBeInTheDocument();
    });

    expect(screen.getByText("Static Analysis")).toBeInTheDocument();
    expect(screen.getByText("Ai Quality")).toBeInTheDocument();
    expect(screen.getByText("Test Coverage")).toBeInTheDocument();
  });

  it("shows the threshold value", async () => {
    await renderDetail();

    await waitFor(() => {
      expect(screen.getByText("0.75")).toBeInTheDocument();
    });
  });
});
