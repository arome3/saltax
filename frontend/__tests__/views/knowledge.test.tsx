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
import CodebaseKnowledgePage from "@/app/intelligence/knowledge/page";

const server = setupServer(...handlers);
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
  usePathname: () => "/intelligence/knowledge",
}));

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: any) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

describe("CodebaseKnowledgePage", () => {
  it("renders the repository search input", () => {
    renderWithProviders(<CodebaseKnowledgePage />);

    expect(
      screen.getByPlaceholderText("Enter repository (e.g. owner/repo)..."),
    ).toBeInTheDocument();
    expect(screen.getByText("Explore")).toBeInTheDocument();
  });

  it("shows the empty state prompting the user to enter a repo name", () => {
    renderWithProviders(<CodebaseKnowledgePage />);

    expect(
      screen.getByText("Enter a repository name to explore"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("e.g. owner/repository"),
    ).toBeInTheDocument();
  });
});
