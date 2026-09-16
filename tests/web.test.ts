import { describe, it, expect, afterAll, beforeAll } from "vitest";
import fs from "fs";
import path from "path";
import type { Server } from "http";
import type { AddressInfo } from "net";
import { fileURLToPath } from "url";
import { startServer } from "../src/web/server";
import { scanSource } from "../src/web/scan";
import type { JsonReport } from "../src/reporting/json";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SAFE = fs.readFileSync(path.join(ROOT, "examples", "safe_vault.rs"), "utf-8");
const VULNERABLE = fs.readFileSync(path.join(ROOT, "examples", "vulnerable_vault.rs"), "utf-8");

let server: Server;
let base: string;

beforeAll(async () => {
  server = startServer({ port: 0 });
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address() as AddressInfo;
  base = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function get(pathname: string): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}${pathname}`);
  // All current callers only need the parsed JSON; a Fetch body cannot be
  // consumed twice, so no separate text() read is attempted.
  return { status: res.status, body: await res.json() };
}

async function postScan(body: string): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  return { status: res.status, body: await res.json() };
}

const scanJson = (source: unknown) => JSON.stringify({ source });

describe("GET /api/health", () => {
  it("returns 200 with the expected JSON", async () => {
    const res = await get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });
});

describe("POST /api/scan", () => {
  it("returns zero findings for the safe demo contract", async () => {
    const res = await postScan(scanJson(SAFE));
    expect(res.status).toBe(200);
    expect(res.body.summary.findingCount).toBe(0);
    expect(res.body.findings).toEqual([]);
  });

  it("returns findings for the vulnerable demo contract", async () => {
    const res = await postScan(scanJson(VULNERABLE));
    expect(res.status).toBe(200);
    expect(res.body.summary.findingCount).toBeGreaterThan(0);

    const ruleIds = res.body.findings.map((f: any) => f.ruleId) as string[];
    expect(ruleIds).toContain("AP-AUTH-001");
    expect(ruleIds).toContain("AP-CALL-001");
    expect(ruleIds).toContain("AP-ARITH-001");
    expect(ruleIds).toContain("AP-UPG-001");
  });

  it("exposes rule ids, severity, confidence, remediation and file info", async () => {
    const res = await postScan(scanJson(VULNERABLE));
    const report = res.body as JsonReport;

    expect(report.tool.name).toBe("auditpulse");
    for (const finding of report.findings) {
      expect(finding.ruleId).toMatch(/^AP-/);
      expect(["critical", "high", "medium", "low"]).toContain(finding.severity);
      expect(typeof finding.message).toBe("string");
      expect(finding.location.line).toBeGreaterThan(0);
      expect(finding.location.file).toBe("submitted-source.rs");
    }

    const auth = report.findings.find((f) => f.ruleId === "AP-AUTH-001");
    expect(auth).toBeDefined();
    expect(auth!.confidence).toBe("high");
    expect(auth!.remediation).toContain("require_auth");

    const sum = Object.values(report.summary.bySeverity).reduce((a, b) => a + b, 0);
    expect(sum).toBe(report.summary.findingCount);
  });

  it("rejects invalid input with a controlled 400 error", async () => {
    for (const bad of ["", "not json", "[1,2]", "42", '{"source": 7}', '{"source": "   "}']) {
      const res = await postScan(bad);
      expect(res.status).toBe(400);
      expect(typeof res.body.error).toBe("string");
      expect(res.body.error.length).toBeGreaterThan(0);
    }
  });

  it("rejects oversized bodies with 413", async () => {
    const big = "f".repeat(300 * 1024);
    const res = await postScan(scanJson(big));
    expect(res.status).toBe(413);
  });
});

describe("GET /api/examples/:name", () => {
  it("serves the two demo contracts", async () => {
    const safe = await get("/api/examples/safe");
    expect(safe.status).toBe(200);
    expect(safe.body.name).toBe("safe_vault.rs");
    expect(safe.body.source).toBe(SAFE);

    const vulnerable = await get("/api/examples/vulnerable");
    expect(vulnerable.status).toBe(200);
    expect(vulnerable.body.name).toBe("vulnerable_vault.rs");
    expect(vulnerable.body.source).toBe(VULNERABLE);
  });

  it("returns a controlled 404 for unknown names", async () => {
    const res = await get("/api/examples/nope");
    expect(res.status).toBe(404);
    expect(typeof res.body.error).toBe("string");
  });
});

describe("dashboard", () => {
  it("serves the AuditPulse UI at /", async () => {
    const res = await fetch(base);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("AUDITPULSE");
    expect(html).toContain("Soroban Security");
  });

  it("returns 404 JSON for unknown paths", async () => {
    const res = await get("/definitely/not/here");
    expect(res.status).toBe(404);
    expect(typeof res.body.error).toBe("string");
  });
});

describe("scanSource (in-memory, no HTTP)", () => {
  it("scans through the existing engine and matches the CLI finding model", () => {
    const report = scanSource(VULNERABLE);
    expect(report.summary.filesScanned).toBe(1);
    expect(report.summary.findingCount).toBeGreaterThan(0);
    expect(scanSource(SAFE).summary.findingCount).toBe(0);
  });
});
