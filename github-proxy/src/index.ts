/**
 * SaltaX GitHub Webhook Proxy
 *
 * Stateless Express server that forwards incoming GitHub webhook payloads
 * to the Python backend.  No HMAC validation here — that happens in Python.
 */

import express, { type Request, type Response } from "express";
import { identityRouter } from "./identity-bridge.js";

const PORT = parseInt(process.env["PORT"] ?? "8081", 10);
const FORWARD_URL =
  process.env["FORWARD_URL"] ?? "http://127.0.0.1:8080/webhook/github";
const FORWARD_TIMEOUT_MS = 9000; // Under GitHub's 10s delivery timeout

const app = express();

// Identity routes need JSON body parsing — mount BEFORE the raw body middleware.
app.use("/identity", express.json({ limit: "1mb" }));
app.use("/identity", identityRouter);

// Preserve the raw body as a Buffer — required for downstream HMAC validation.
app.use(express.raw({ type: "application/json", limit: "10mb" }));

/** Extract the first value from a potentially multi-value header. */
function headerString(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

// ── Health check ────────────────────────────────────────────────────────────

app.get("/healthz", (_req: Request, res: Response) => {
  res.json({ status: "ok" });
});

// ── Webhook forwarding ──────────────────────────────────────────────────────

app.post("/webhook", async (req: Request, res: Response) => {
  const signature = headerString(req.headers["x-hub-signature-256"]);
  const event = headerString(req.headers["x-github-event"]);
  const delivery = headerString(req.headers["x-github-delivery"]);

  if (!signature || !event || !delivery) {
    res.status(400).json({ error: "Missing required GitHub headers" });
    return;
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Hub-Signature-256": signature,
    "X-GitHub-Event": event,
    "X-GitHub-Delivery": delivery,
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FORWARD_TIMEOUT_MS);

  try {
    const response = await fetch(FORWARD_URL, {
      method: "POST",
      headers,
      body: new Uint8Array(req.body as Buffer),
      signal: controller.signal,
    });

    res.status(response.status).json(await response.json().catch(() => ({})));
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      console.error("Webhook forward timed out after", FORWARD_TIMEOUT_MS, "ms");
      res.status(504).json({ error: "Backend did not respond in time" });
    } else {
      console.error("Failed to forward webhook:", err);
      res.status(502).json({ error: "Failed to forward webhook to backend" });
    }
  } finally {
    clearTimeout(timeoutId);
  }
});

// ── Start server ────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`SaltaX GitHub Proxy listening on port ${PORT}`);
  console.log(`Forwarding to ${FORWARD_URL}`);
});
