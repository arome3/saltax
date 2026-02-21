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
import AttestationExplorerPage from "@/app/attestation/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/attestation",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

describe("AttestationExplorerPage", () => {
  it("renders the search bar and search button", () => {
    renderWithProviders(<AttestationExplorerPage />);

    expect(
      screen.getByPlaceholderText(
        "Search attestation ID, hash, signer...",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Search")).toBeInTheDocument();
  });

  it("renders the filter tabs", () => {
    renderWithProviders(<AttestationExplorerPage />);

    expect(screen.getByText("All")).toBeInTheDocument();
    expect(screen.getByText("Pipeline")).toBeInTheDocument();
    expect(screen.getByText("Patrol")).toBeInTheDocument();
    expect(screen.getByText("Audit")).toBeInTheDocument();
  });

  it("shows attestation results from the API", async () => {
    renderWithProviders(<AttestationExplorerPage />);

    await waitFor(() => {
      expect(screen.getByText("valid")).toBeInTheDocument();
    });
  });

  it("shows the detail panel placeholder when no attestation is selected", async () => {
    renderWithProviders(<AttestationExplorerPage />);

    await waitFor(() => {
      expect(
        screen.getByText("Select an attestation to view details"),
      ).toBeInTheDocument();
    });
  });
});
