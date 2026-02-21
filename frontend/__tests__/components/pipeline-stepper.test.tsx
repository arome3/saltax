import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  PipelineStepper,
  type PipelineStage,
} from "@/components/saltax/pipeline-stepper";

describe("PipelineStepper", () => {
  const stages: PipelineStage[] = [
    { label: "Triage", status: "completed" },
    { label: "Scoring", status: "active" },
    { label: "Verdict", status: "pending" },
  ];

  it("renders a list with role='list'", () => {
    render(<PipelineStepper stages={stages} />);
    expect(screen.getByRole("list")).toBeInTheDocument();
  });

  it("renders one listitem per stage", () => {
    render(<PipelineStepper stages={stages} />);
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(3);
  });

  it("displays all stage labels", () => {
    render(<PipelineStepper stages={stages} />);
    expect(screen.getByText("Triage")).toBeInTheDocument();
    expect(screen.getByText("Scoring")).toBeInTheDocument();
    expect(screen.getByText("Verdict")).toBeInTheDocument();
  });

  it("renders a single stage without connector lines", () => {
    render(<PipelineStepper stages={[{ label: "Only", status: "active" }]} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(1);
    expect(screen.getByText("Only")).toBeInTheDocument();
  });

  it("handles a failed stage in the sequence", () => {
    const withFailed: PipelineStage[] = [
      { label: "Triage", status: "completed" },
      { label: "Scoring", status: "failed" },
      { label: "Verdict", status: "pending" },
    ];
    render(<PipelineStepper stages={withFailed} />);
    expect(screen.getByText("Scoring")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
  });

  it("has an accessible label on the list", () => {
    render(<PipelineStepper stages={stages} />);
    expect(screen.getByLabelText("Pipeline stages")).toBeInTheDocument();
  });
});
