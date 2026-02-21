import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ActivityFeedItem } from "@/components/saltax/activity-feed-item";
import type { LogEvent } from "@/types";

function makeEvent(overrides: Partial<LogEvent> = {}): LogEvent {
  return {
    timestamp: new Date(Date.now() - 120_000).toISOString(), // 2 minutes ago
    level: "INFO",
    logger: "saltax.pipeline",
    message: "PR review completed for owner/repo#42",
    ...overrides,
  };
}

describe("ActivityFeedItem", () => {
  it("renders the event message", () => {
    render(<ActivityFeedItem event={makeEvent()} />);
    expect(
      screen.getByText("PR review completed for owner/repo#42"),
    ).toBeInTheDocument();
  });

  it("displays relative time for the timestamp", () => {
    render(<ActivityFeedItem event={makeEvent()} />);
    // 2 minutes ago
    expect(screen.getByText("2m ago")).toBeInTheDocument();
  });

  it("shows repo name when repo is present", () => {
    render(
      <ActivityFeedItem
        event={makeEvent({ repo: "owner/my-repo" })}
      />,
    );
    expect(screen.getByText("owner/my-repo")).toBeInTheDocument();
  });

  it("does not show repo when repo is absent", () => {
    render(
      <ActivityFeedItem
        event={makeEvent({ repo: undefined, message: "Pipeline completed" })}
      />,
    );
    // The repo-specific span element should not render
    const items = screen.queryAllByText(/owner\//);
    // Only the message may contain text, but no separate repo span
    expect(items.length).toBe(0);
  });

  it("renders with an icon that is aria-hidden", () => {
    const { container } = render(<ActivityFeedItem event={makeEvent()} />);
    const icon = container.querySelector("[aria-hidden='true']");
    expect(icon).toBeInTheDocument();
  });

  it("renders events at different severity levels", () => {
    const levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] as const;
    for (const level of levels) {
      const { unmount } = render(
        <ActivityFeedItem event={makeEvent({ level, message: `${level} event` })} />,
      );
      expect(screen.getByText(`${level} event`)).toBeInTheDocument();
      unmount();
    }
  });
});
