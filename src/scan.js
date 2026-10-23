import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";
import { maskKey, scanLine } from "./detectors.js";

// Directories that are never worth scanning (dependencies, build output, VCS internals).
const SKIP_DIRS = new Set([
  ".git", "node_modules", ".next", ".nuxt", ".svelte-kit", ".turbo", ".vercel", ".cache",
  "dist", "build", "out", "coverage", "vendor", ".venv", "venv", "__pycache__", "target", ".gradle",
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|7z|rar|mp[34]|mov|woff2?|ttf|otf|eot|exe|dll|so|dylib|bin|lockb|sqlite|db)$/i;
const PATCH_FLAGS = ["--no-color", "--no-ext-diff", "--unified=0"];

/**
 * Where a key was seen. Severity order: about to be committed or pushed first, local is fine.
 * @typedef {"staged" | "unpushed" | "new" | "committed" | "public" | "history" | "untracked" | "local"} Exposure
 * @typedef {{ file: string, line?: number, commit?: string, date?: string, exposure: Exposure }} Location
 * @typedef {{ fingerprint: string, provider: string, masked: string, rotateUrl?: string, rotateHint?: string, locations: Location[] }} Finding
 */

export const EXPOSURE_RANK = { staged: 0, unpushed: 1, new: 2, committed: 3, public: 4, history: 5, untracked: 6, local: 7 };

function git(cwd, args) {
  const r = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  return r.status === 0 ? r.stdout : null;
}

export function isGitRepo(dir) {
  return git(dir, ["rev-parse", "--is-inside-work-tree"])?.trim() === "true";
}

function gitFileSet(root, args) {
  const out = git(root, ["ls-files", "-z", ...args]);
  return new Set(out ? out.split("\0").filter(Boolean).map((p) => p.replace(/\\/g, "/")) : []);
}

async function* walk(dir, root) {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.isSymbolicLink()) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(full, root);
    } else if (e.isFile() && !BINARY_EXT.test(e.name)) {
      yield path.relative(root, full).replace(/\\/g, "/");
    }
  }
}

async function scanFile(fullPath, onMatch) {
  const stat = await fs.stat(fullPath).catch(() => null);
  if (!stat || stat.size > MAX_FILE_BYTES) return;
  const rl = createInterface({ input: createReadStream(fullPath, { encoding: "utf8" }), crlfDelay: Infinity });
  let n = 0;
  for await (const line of rl) {
    n++;
    if (line.includes("\0")) return; // binary content
    for (const hit of scanLine(line)) onMatch(hit, n);
  }
}

/**
 * Streams a git diff or `git log -p` (run with --unified=0) and reports keys on added lines,
 * with the file, the line number in the new version, and the commit when there is one.
 * Resolves with the number of commits seen and the files touched.
 */
function scanPatch(root, gitArgs, onMatch, onProgress) {
  return new Promise((resolve, reject) => {
    const child = spawn("git", ["-C", root, ...gitArgs], { stdio: ["ignore", "pipe", "ignore"] });
    const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
    let commit = "";
    let date = "";
    let file = "";
    let lineNo = 0;
    let commits = 0;
    const files = new Set();
    rl.on("line", (line) => {
      if (line.startsWith("\0")) {
        [commit, date] = line.slice(1).split(" ");
        commits++;
        if (commits % 200 === 0) onProgress?.(commits);
      } else if (line.startsWith("+++ ")) {
        file = diffPath(line.slice(4));
        if (file) files.add(file);
      } else if (line.startsWith("@@")) {
        lineNo = Number(/\+(\d+)/.exec(line)?.[1] ?? 0);
      } else if (line.startsWith("+") && file) {
        for (const hit of scanLine(line.slice(1))) onMatch(hit, { file, line: lineNo, commit, date });
        lineNo++;
      }
    });
    child.on("error", reject);
    child.on("close", () => resolve({ commits, files }));
  });
}

/**
 * The path from a "+++ b/path" diff header. Git appends a tab to paths containing spaces and
 * wraps unusual paths in C-style quotes ("b/caf\303\251.js"); "/dev/null" means a deleted file.
 */
function diffPath(header) {
  let p = header.replace(/\t$/, "");
  if (p.startsWith('"') && p.endsWith('"')) {
    const bytes = [];
    for (let i = 1; i < p.length - 1; i++) {
      const ch = p[i];
      if (ch !== "\\") {
        bytes.push(...Buffer.from(ch));
        continue;
      }
      const next = p[++i];
      if (/[0-7]/.test(next)) {
        bytes.push(parseInt(p.slice(i, i + 3), 8));
        i += 2;
      } else {
        bytes.push({ n: 10, t: 9, r: 13, '"': 34, "\\": 92 }[next] ?? next.charCodeAt(0));
      }
    }
    p = Buffer.from(bytes).toString("utf8");
  }
  return p.startsWith("b/") ? p.slice(2) : "";
}

const fingerprint = (key) => createHash("sha256").update(key).digest("hex");

function newFinding(hit) {
  return {
    fingerprint: fingerprint(hit.key),
    provider: hit.detector.provider,
    masked: hit.detector.mask?.(hit.key) ?? maskKey(hit.key),
    rotateUrl: hit.detector.rotateUrl,
    rotateHint: hit.detector.rotateHint,
    locations: [],
  };
}

/**
 * Scans a directory. Never stores or returns a full key: only its SHA-256 and a masked form.
 * @param {string} root
 * @param {{ history?: boolean, onProgress?: (msg: string) => void }} [opts]
 */
export async function scan(root, opts = {}) {
  root = path.resolve(root);
  const repo = isGitRepo(root);
  /** @type {Map<string, Finding>} */
  const findings = new Map();
  const stats = { files: 0, commits: 0, repo, historyScanned: false };

  const record = (hit, loc) => {
    const fp = fingerprint(hit.key);
    let f = findings.get(fp);
    if (!f) {
      f = newFinding(hit);
      findings.set(fp, f);
    }
    const exposure = hit.publicPrefix && loc.exposure !== "history" ? "public" : loc.exposure;
    const dup = f.locations.some((l) => l.file === loc.file && l.line === loc.line && l.commit === loc.commit);
    if (!dup) f.locations.push({ ...loc, exposure });
  };

  // 1. Working tree
  const tracked = repo ? gitFileSet(root, ["--cached"]) : new Set();
  const untracked = repo ? gitFileSet(root, ["--others", "--exclude-standard"]) : new Set();
  for await (const rel of walk(root, root)) {
    stats.files++;
    if (stats.files % 500 === 0) opts.onProgress?.(`Scanned ${stats.files} files`);
    const exposure = !repo ? "untracked" : tracked.has(rel) ? "committed" : untracked.has(rel) ? "untracked" : "local";
    await scanFile(path.join(root, rel), (hit, line) => record(hit, { file: rel, line, exposure }));
  }

  // 2. Git history: keys that were committed once stay readable forever, even after deletion.
  if (repo && opts.history !== false) {
    opts.onProgress?.("Scanning git history");
    const currentlyCommitted = new Set();
    for (const f of findings.values()) {
      if (f.locations.some((l) => l.exposure === "committed" || l.exposure === "public")) currentlyCommitted.add(f.fingerprint);
    }
    ({ commits: stats.commits } = await scanPatch(
      root,
      ["log", "--all", "-p", ...PATCH_FLAGS, "--format=%x00%H %aI"],
      (hit, { file, commit, date }) => {
        const fp = fingerprint(hit.key);
        // A key that is still committed is already reported at its current location.
        if (currentlyCommitted.has(fp)) return;
        const existing = findings.get(fp);
        if (existing?.locations.some((l) => l.exposure === "history")) return; // first sighting is enough
        record(hit, { file, commit: commit.slice(0, 8), date: date?.slice(0, 10), exposure: "history" });
      },
      (n) => opts.onProgress?.(`Scanned ${n} commits`),
    ));
    stats.historyScanned = true;
  }

  const list = [...findings.values()].sort((a, b) => worst(a) - worst(b));
  return { root, stats, findings: list };
}

/**
 * Hook mode: scans only what is about to leave the machine.
 *   "staged": changes staged for the next commit (pre-commit hook)
 *   "push":   commits on this branch that are on no remote yet (pre-push hook)
 *   "range":  commits after `since` (pull requests and CI: only what this change adds)
 * Fast, and it never blocks a change over old keys outside it.
 * @param {string} root
 * @param {"staged" | "push" | "range"} mode
 * @param {string} [since] git ref for "range", e.g. origin/main or a commit sha
 */
export async function scanChanges(root, mode, since) {
  root = path.resolve(root);
  if (!isGitRepo(root)) throw new Error("not a git repository, so there are no staged or unpushed changes to check");
  /** @type {Map<string, Finding>} */
  const findings = new Map();
  const exposure = mode === "staged" ? "staged" : mode === "range" ? "new" : "unpushed";
  if (mode === "range" && (!since || since.startsWith("-") || !git(root, ["rev-parse", "--verify", "--quiet", `${since}^{commit}`]))) {
    throw new Error(`cannot find "${since}". In CI, check out with full history (fetch-depth: 0).`);
  }
  const args =
    mode === "staged"
      ? ["diff", "--cached", ...PATCH_FLAGS, "--diff-filter=ACMR"]
      : mode === "range"
        ? ["log", "-p", ...PATCH_FLAGS, "--format=%x00%H %aI", `${since}..HEAD`]
        : ["log", "-p", ...PATCH_FLAGS, "--format=%x00%H %aI", "HEAD", "--not", "--remotes"];

  const { commits, files } = await scanPatch(root, args, (hit, loc) => {
    const fp = fingerprint(hit.key);
    let f = findings.get(fp);
    if (!f) {
      f = newFinding(hit);
      findings.set(fp, f);
    }
    const location = { file: loc.file, line: loc.line, exposure };
    if (loc.commit) Object.assign(location, { commit: loc.commit.slice(0, 8), date: loc.date?.slice(0, 10) });
    if (!f.locations.some((l) => l.file === location.file && l.line === location.line && l.commit === location.commit)) {
      f.locations.push(location);
    }
  });

  return { root, stats: { mode, since, files: files.size, commits, repo: true, historyScanned: false }, findings: [...findings.values()] };
}

export function worst(f) {
  return Math.min(...f.locations.map((l) => EXPOSURE_RANK[l.exposure]));
}
