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
import StakingContributorsPage from "@/app/staking/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/staking",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

describe("StakingContributorsPage", () => {
  it("renders the staking calculator section", () => {
    renderWithProviders(<StakingContributorsPage />);

    expect(screen.getByText("Staking Calculator")).toBeInTheDocument();
    expect(
      screen.getByLabelText("Stake Amount (ETH)"),
    ).toBeInTheDocument();
  });

  it("shows outcome scenarios in the staking calculator", () => {
    renderWithProviders(<StakingContributorsPage />);

    expect(screen.getByText("Outcome Scenarios")).toBeInTheDocument();
    expect(
      screen.getByText("Approved, no challenge"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Approved, challenge rejected"),
    ).toBeInTheDocument();
  });

  it("renders the contributor leaderboard with data after loading", async () => {
    renderWithProviders(<StakingContributorsPage />);

    await waitFor(() => {
      expect(
        screen.getByText("Contributor Leaderboard"),
      ).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByText("alice")).toBeInTheDocument();
    });
  });

  it("shows leaderboard table headers", async () => {
    renderWithProviders(<StakingContributorsPage />);

    await waitFor(() => {
      expect(screen.getByText("GitHub Login")).toBeInTheDocument();
    });

    expect(screen.getByText("Total")).toBeInTheDocument();
    expect(screen.getByText("Approved")).toBeInTheDocument();
    expect(screen.getByText("Rejected")).toBeInTheDocument();
    expect(screen.getByText("Reputation")).toBeInTheDocument();
  });
});
