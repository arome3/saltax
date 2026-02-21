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
import PaidAuditPage from "@/app/audit/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/audit",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

describe("PaidAuditPage", () => {
  it("renders the repository URL input field", () => {
    renderWithProviders(<PaidAuditPage />);

    expect(screen.getByLabelText("GitHub Repository URL")).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText("https://github.com/owner/repo"),
    ).toBeInTheDocument();
  });

  it("renders the commit SHA input field", () => {
    renderWithProviders(<PaidAuditPage />);

    expect(screen.getByLabelText("Commit SHA")).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText("e.g. abc123def456..."),
    ).toBeInTheDocument();
  });

  it("renders the scope selector with all options", () => {
    renderWithProviders(<PaidAuditPage />);

    expect(screen.getByText("Audit Scope")).toBeInTheDocument();
    expect(screen.getByText("Security Only")).toBeInTheDocument();
    expect(screen.getByText("Quality Only")).toBeInTheDocument();
    // "Full Audit" appears in both scope button and payment summary (default scope)
    expect(screen.getAllByText("Full Audit").length).toBeGreaterThanOrEqual(1);
  });

  it("renders the payment summary section", () => {
    renderWithProviders(<PaidAuditPage />);

    expect(screen.getByText("Payment Summary")).toBeInTheDocument();
    expect(screen.getByText("Scope")).toBeInTheDocument();
  });
});
