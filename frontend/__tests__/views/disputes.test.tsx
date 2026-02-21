import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
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
import DisputeResolutionPage from "@/app/verification/disputes/page";

// Override MUST come BEFORE base handlers — MSW matches first handler that fits
const disputeHandlers = [
  http.get("/api/v1/verification/windows", () => {
    return HttpResponse.json({ windows: [], count: 0 });
  }),
  ...handlers,
];

const server = setupServer(...disputeHandlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/verification/disputes",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

describe("DisputeResolutionPage", () => {
  it("renders the empty disputes state when no disputes exist", async () => {
    renderWithProviders(<DisputeResolutionPage />);

    await waitFor(() => {
      expect(screen.getByText("No disputes")).toBeInTheDocument();
    });

    expect(
      screen.getByText(
        "Challenged verification windows will appear here",
      ),
    ).toBeInTheDocument();
  });

  it("does not render active disputes heading when empty", async () => {
    renderWithProviders(<DisputeResolutionPage />);

    await waitFor(() => {
      expect(screen.getByText("No disputes")).toBeInTheDocument();
    });

    // The EmptyDisputes component replaces the entire page, so no sections
    expect(
      screen.queryByText("Active Disputes"),
    ).not.toBeInTheDocument();
  });
});
