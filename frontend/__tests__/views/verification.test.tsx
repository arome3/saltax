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
import VerificationPage from "@/app/verification/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/verification",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

describe("VerificationPage", () => {
  it("renders the Active Windows section heading", async () => {
    renderWithProviders(<VerificationPage />);

    await waitFor(() => {
      expect(screen.getByText("Active Windows")).toBeInTheDocument();
    });
  });

  it("shows a verification window card with PR number", async () => {
    renderWithProviders(<VerificationPage />);

    await waitFor(() => {
      expect(screen.getByText("PR#42")).toBeInTheDocument();
    });
  });

  it("displays countdown timer in the window card", async () => {
    renderWithProviders(<VerificationPage />);

    await waitFor(() => {
      expect(screen.getByText("Closes in")).toBeInTheDocument();
    });

    // The countdown timer should render with a time-remaining aria-label
    const timer = screen.getByLabelText(/Time remaining/);
    expect(timer).toBeInTheDocument();
  });

  it("renders the Recently Resolved section heading", async () => {
    renderWithProviders(<VerificationPage />);

    await waitFor(() => {
      expect(screen.getByText("Recently Resolved")).toBeInTheDocument();
    });
  });
});
