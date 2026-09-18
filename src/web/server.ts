import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { scanSource } from "./scan.js";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";

/**
 * Demo contracts served to the dashboard. Fixed allowlist: request data
 * never picks a path on the server filesystem.
 */
const EXAMPLES: Record<string, string> = {
  safe: "examples/safe_vault.rs",
  vulnerable: "examples/vulnerable_vault.rs",
};

/**
 * Minimal HTTP layer for the AuditPulse web demo.
 *
 * The server owns transport concerns only: routing, request-size limits and
 * static files. All analysis is delegated to scanSource(), which runs the
 * existing CLI engine — no scanning logic lives here.
 */

const MAX_BODY_BYTES = 256 * 1024; // generous for source files, still a limit
const MAX_DRAIN_BYTES = 1024 * 1024; // how much of an oversized body we tolerate reading

export interface WebServerOptions {
  port?: number;
  host?: string;
}

export function startServer(options: WebServerOptions = {}): http.Server {
  const server = http.createServer((req, res) => {
    void handle(req, res);
  });
  const port = options.port ?? 4646;
  const host = options.host ?? "127.0.0.1";

  server.listen(port, host, () => {
    console.log(`${TOOL_NAME} web demo listening on http://${host}:${port}`);
  });
  return server;
}

async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");

  try {
    if (req.method === "GET" && url.pathname === "/api/health") {
      return json(res, 200, { status: "ok" });
    }

    if (req.method === "POST" && url.pathname === "/api/scan") {
      return await handleScan(req, res);
    }

    const example = req.method === "GET" && url.pathname.match(/^\/api\/examples\/(\w+)$/);
    if (example) {
      return serveExample(example[1]!, res);
    }

    if (req.method === "GET") {
      return serveStatic(url.pathname, res);
    }

    res.setHeader("Allow", "GET, POST");
    json(res, 405, { error: "Method not allowed" });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    json(res, 500, { error: message });
  }
}

async function handleScan(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const body = await readBody(req);
  if (body === null) {
    return json(res, 413, { error: `Request body too large (limit: ${MAX_BODY_BYTES} bytes)` });
  }

  let payload: unknown;
  try {
    payload = body.length === 0 ? {} : JSON.parse(body);
  } catch {
    return json(res, 400, { error: "Request body must be valid JSON" });
  }

  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return json(res, 400, { error: 'Request body must be a JSON object like {"source": "..."}' });
  }

  const source = (payload as Record<string, unknown>)["source"];
  if (typeof source !== "string") {
    return json(res, 400, { error: 'Field "source" is required and must be a string of Rust source code' });
  }
  if (source.trim().length === 0) {
    return json(res, 400, { error: 'Field "source" must not be empty' });
  }

  json(res, 200, scanSource(source));
}

/**
 * Reads the request body as UTF-8 text. Returns null when the body exceeds
 * the size limit. Oversized bodies are drained (up to a small grace cap)
 * instead of aborted mid-stream so the client can still receive the 413
 * response; anything beyond the grace cap gets the socket cut.
 */
function readBody(req: http.IncomingMessage): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let overLimit = false;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (!overLimit && size > MAX_BODY_BYTES) {
        overLimit = true;
        chunks.length = 0; // discard buffered data; the request is rejected anyway
      }
      if (overLimit) {
        if (size > MAX_BODY_BYTES + MAX_DRAIN_BYTES) {
          req.destroy(); // abusive client: cut the connection
          resolve(null);
        }
        return; // discard drained data
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(overLimit ? null : Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function serveExample(name: string, res: http.ServerResponse): void {
  const relPath = EXAMPLES[name];
  const absPath = relPath ? path.join(repoRoot(), relPath) : null;
  if (!absPath || !fs.existsSync(absPath)) {
    return json(res, 404, { error: `Example not found: ${name}` });
  }
  json(res, 200, { name: path.basename(relPath!), source: fs.readFileSync(absPath, "utf-8") });
}

/** Repository root, derived from this file's location (works for src/ and dist/). */
function repoRoot(): string {
  return path.resolve(webRoot(), "..", "..");
}

function serveStatic(pathname: string, res: http.ServerResponse): void {
  // Only two fixed files are ever served; there is no user-controlled path
  // resolution, so nothing on the server filesystem is reachable by request.
  if (pathname === "/" || pathname === "/index.html") {
    // public/ lives at the repository root in both the src/ and dist/ layouts.
    const index = path.join(repoRoot(), "public", "index.html");
    if (fs.existsSync(index)) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(fs.readFileSync(index));
      return;
    }
  }

  json(res, 404, { error: "Not found" });
}

function webRoot(): string {
  return path.dirname(fileURLToPath(import.meta.url));
}

function json(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}

// Allow direct execution: node dist/web/server.js [--port N]
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, "/")}`).href) {
  const portFlag = process.argv.indexOf("--port");
  const port = portFlag >= 0 ? Number(process.argv[portFlag + 1]) : undefined;
  startServer({ port: Number.isFinite(port) ? port : undefined });
}
