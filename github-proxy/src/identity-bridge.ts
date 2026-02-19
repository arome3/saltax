/**
 * ERC-8004 Identity Bridge — Express routes wrapping the Agent0 SDK.
 *
 * Lazy-initializes the SDK singleton on first request using env vars.
 * All routes return structured JSON; errors are caught and returned as 500.
 */

import { Router, type Request, type Response } from "express";
import { SDK, type Agent } from "agent0-sdk";
import type { ChainId, AgentId } from "agent0-sdk";

let sdkInstance: SDK | null = null;
let agentInstance: Agent | null = null;

const PRIVATE_KEY = process.env["IDENTITY_PRIVATE_KEY"] ?? "";
const RPC_URL =
  process.env["IDENTITY_RPC_URL"] ??
  "https://ethereum-sepolia-rpc.publicnode.com";
const CHAIN_ID = parseInt(process.env["IDENTITY_CHAIN_ID"] ?? "11155111", 10);
const PINATA_JWT = process.env["PINATA_JWT"] ?? "";

/**
 * Lazily initialize the Agent0 SDK.
 */
function ensureSDK(): SDK {
  if (sdkInstance) return sdkInstance;

  sdkInstance = new SDK({
    chainId: CHAIN_ID as ChainId,
    rpcUrl: RPC_URL,
    privateKey: PRIVATE_KEY || undefined,
    ipfs: PINATA_JWT ? "pinata" : undefined,
    pinataJwt: PINATA_JWT || undefined,
  });

  console.log("Agent0 SDK initialized");
  return sdkInstance;
}

export const identityRouter = Router();

// ── POST /register — Register a new agent identity ────────────────────────

identityRouter.post("/register", async (req: Request, res: Response) => {
  try {
    const sdk = ensureSDK();
    const { name, description } = req.body ?? {};

    const agentName = name ?? "SaltaX";
    const agentDesc = description ?? "Sovereign Code Organism";

    let result: { agentId: string; agentURI: string; recovered: boolean };

    try {
      // createAgent returns an in-memory Agent object
      const agent = sdk.createAgent(agentName, agentDesc);
      agentInstance = agent;

      // Register on-chain via IPFS (pins registration file)
      const txHandle = await agent.registerIPFS();
      const mined = await txHandle.waitMined();
      const agentId = mined.result?.agentId ?? agent.agentId ?? "";
      const agentURI = agent.agentURI ?? "";

      result = {
        agentId: String(agentId),
        agentURI: String(agentURI),
        recovered: false,
      };
    } catch (err: unknown) {
      // Handle "already registered" — try to recover existing identity
      const msg = String(
        err instanceof Error ? err.message : err
      ).toLowerCase();
      if (
        msg.includes("already registered") ||
        msg.includes("already exists")
      ) {
        console.log(
          "Agent already registered, attempting recovery via loadAgent"
        );
        // We don't have the agentId yet — this is a fallback
        // The caller should use GET /agent to look up by address
        res.status(409).json({
          error: "Agent already registered",
          detail: "Use GET /identity/agent to look up the existing agent",
        });
        return;
      }
      throw err;
    }

    res.json(result);
  } catch (err) {
    console.error("Identity registration failed:", err);
    res.status(500).json({
      error: "Registration failed",
      detail: err instanceof Error ? err.message : String(err),
    });
  }
});

// ── GET /agent — Look up agent details ────────────────────────────────────

identityRouter.get("/agent", async (req: Request, res: Response) => {
  try {
    const sdk = ensureSDK();
    const agentId = req.query["agentId"] as string | undefined;
    if (!agentId) {
      res.status(400).json({ error: "Missing agentId query parameter" });
      return;
    }

    const agent = await sdk.getAgent(agentId as AgentId);
    if (!agent) {
      res.status(404).json({ error: "Agent not found" });
      return;
    }

    res.json(agent);
  } catch (err) {
    console.error("Get agent failed:", err);
    res.status(500).json({
      error: "Failed to get agent",
      detail: err instanceof Error ? err.message : String(err),
    });
  }
});

// ── POST /feedback — Submit reputation feedback ───────────────────────────

identityRouter.post("/feedback", async (req: Request, res: Response) => {
  try {
    const sdk = ensureSDK();
    const { agentId, value, tag1, tag2 } = req.body ?? {};
    if (!agentId || value === undefined) {
      res.status(400).json({ error: "Missing agentId or value" });
      return;
    }

    const handle = await sdk.giveFeedback(
      agentId as AgentId,
      value,
      tag1 ?? "",
      tag2 ?? ""
    );

    // Wait for the transaction to be mined
    const mined = await handle.waitMined();

    res.json({
      txHash: handle.hash ?? "",
      result: mined.result ?? null,
    });
  } catch (err) {
    console.error("Give feedback failed:", err);
    res.status(500).json({
      error: "Failed to submit feedback",
      detail: err instanceof Error ? err.message : String(err),
    });
  }
});

// ── GET /reputation — Fetch reputation summary ───────────────────────────

identityRouter.get("/reputation", async (req: Request, res: Response) => {
  try {
    const sdk = ensureSDK();
    const agentId = req.query["agentId"] as string | undefined;
    if (!agentId) {
      res.status(400).json({ error: "Missing agentId query parameter" });
      return;
    }

    const summary = await sdk.getReputationSummary(agentId as AgentId);
    res.json(summary);
  } catch (err) {
    console.error("Get reputation failed:", err);
    res.status(500).json({
      error: "Failed to get reputation",
      detail: err instanceof Error ? err.message : String(err),
    });
  }
});
