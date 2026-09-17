#!/usr/bin/env node
/**
 * Publishes the roadmap issues described in scripts/issues/*.md to GitHub.
 *
 * Each issue file is Markdown with a small frontmatter header:
 *
 *   ---
 *   title: <issue title>
 *   labels: enhancement, good first issue
 *   ---
 *   <issue body in Markdown>
 *
 * Dry-run by default: prints title and labels. With --execute and a
 * GITHUB_TOKEN (repo scope) it creates the issues via the REST API,
 * skipping any issue whose title already exists (open or closed), so
 * re-running never produces duplicates.
 *
 * Usage:
 *   node scripts/publish-issues.mjs
 *   GITHUB_TOKEN=... node scripts/publish-issues.mjs --execute
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ISSUES_DIR = path.join(ROOT, "scripts", "issues");

const OWNER = "Emmanuel-Ugochukwu1";
const REPO = "auditpulse-core";
const API = `https://api.github.com/repos/${OWNER}/${REPO}`;

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

/** Parses `--- title/labels ---` frontmatter plus the Markdown body. */
function parseIssueFile(filePath) {
  const text = fs.readFileSync(filePath, "utf-8").replace(/\r\n/g, "\n");
  const match = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
  if (match === null) {
    fail(`${path.basename(filePath)}: expected frontmatter (--- title ... ---)`);
  }
  const header = match[1] ?? "";
  const body = (match[2] ?? "").trim();
  const title = /^title:\s*(.+)$/m.exec(header)?.[1]?.trim();
  const labels = /^labels:\s*(.+)$/m
    .exec(header)?.[1]
    ?.split(",")
    .map((label) => label.trim())
    .filter(Boolean);
  if (title === undefined || title === "" || body === "" || labels === undefined) {
    fail(`${path.basename(filePath)}: frontmatter must include title and labels`);
  }
  return { file: path.basename(filePath), title, labels, body };
}

function loadIssues() {
  const files = fs
    .readdirSync(ISSUES_DIR)
    .filter((name) => name.endsWith(".md"))
    .sort();
  if (files.length === 0) {
    fail(`no issue files found in ${path.relative(ROOT, ISSUES_DIR)}`);
  }
  return files.map((name) => parseIssueFile(path.join(ISSUES_DIR, name)));
}

async function github(pathname, options = {}) {
  const response = await fetch(`${API}${pathname}`, {
    ...options,
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(process.env.GITHUB_TOKEN
        ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
        : {}),
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
  });
  if (response.status === 403 && !process.env.GITHUB_TOKEN) {
    fail(`GitHub API ${pathname} returned 403: this endpoint needs a GITHUB_TOKEN`);
  }
  if (!response.ok) {
    const detail = await response.text();
    fail(`GitHub API ${pathname} failed: ${response.status} ${detail.slice(0, 300)}`);
  }
  return response.json();
}

async function existingTitles() {
  const titles = new Set();
  for (let page = 1; ; page++) {
    const issues = await github(`/issues?state=all&per_page=100&page=${page}`);
    for (const issue of issues) {
      if (!issue.pull_request) titles.add(issue.title.trim().toLowerCase());
    }
    if (issues.length < 100) break;
  }
  return titles;
}

async function main() {
  const execute = process.argv.includes("--execute");
  if (execute && process.env.GITHUB_TOKEN === undefined) {
    fail("GITHUB_TOKEN is required with --execute");
  }

  const issues = loadIssues();
  const known = execute ? await existingTitles() : null;

  let created = 0;
  let skipped = 0;
  for (const issue of issues) {
    if (known !== null && known.has(issue.title.trim().toLowerCase())) {
      console.log(`skip (title exists): ${issue.title}`);
      skipped++;
      continue;
    }
    if (!execute) {
      console.log(`dry-run: ${issue.title}`);
      console.log(`  labels: ${issue.labels.join(", ")}`);
      continue;
    }
    const result = await github("/issues", {
      method: "POST",
      body: JSON.stringify({ title: issue.title, body: issue.body, labels: issue.labels }),
    });
    console.log(`created #${result.number}: ${result.title}`);
    created++;
  }

  console.log(
    `${execute ? `created: ${created}` : "dry-run complete (nothing was created)"}; skipped: ${skipped}; total files: ${issues.length}`,
  );
}

main().catch(fail);
