import { EXPOSURE_RANK, worst } from "./scan.js";

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = {
  bold: paint("1"),
  dim: paint("2"),
  red: paint("31"),
  orange: paint("38;5;202"),
  yellow: paint("33"),
  green: paint("32"),
  cyan: paint("36"),
};

const EXPLAIN = {
  committed: "committed in the repo right now; anyone with repo access can read it",
  public: "uses a public env prefix, so it ships to every visitor's browser",
  history: "deleted from the files but still in git history; every clone has it",
  untracked: "not committed yet; make sure this file is in .gitignore",
  local: "local file, gitignored",
};

export const AT_RISK = new Set(["committed", "public", "history"]);

function where(l) {
  if (l.exposure === "history") return `${l.file} ${c.dim(`(commit ${l.commit}, ${l.date})`)}`;
  return `${l.file}${l.line ? c.dim(`:${l.line}`) : ""}`;
}

export function printReport(result) {
  const { findings, stats } = result;
  const risky = findings.filter((f) => AT_RISK.has(bestExposure(f)));
  const check = findings.filter((f) => bestExposure(f) === "untracked");
  const ok = findings.filter((f) => bestExposure(f) === "local");
  const out = [];

  out.push("");
  out.push(`${c.orange(c.bold("leakmoat"))} ${c.dim("scan")}  ${c.dim(result.root)}`);
  const scope = [`${stats.files} files`];
  if (stats.historyScanned) scope.push(`${stats.commits} commits of git history`);
  else if (!stats.repo) scope.push("not a git repo, history skipped");
  out.push(c.dim(`Scanned ${scope.join(" and ")}. Nothing left your machine.`));
  out.push("");

  if (findings.length === 0) {
    out.push(`${c.green("✔")} ${c.bold("No exposed keys or secrets found.")}`);
    out.push("");
    return out.join("\n");
  }

  if (risky.length) {
    out.push(c.red(c.bold(`✖ ${risky.length} exposed secret${risky.length > 1 ? "s" : ""}: rotate ${risky.length > 1 ? "these" : "this"} now`)));
    out.push("");
    for (const f of risky) out.push(...block(f, c.red));
  }
  if (check.length) {
    out.push(c.yellow(c.bold(`! ${check.length} secret${check.length > 1 ? "s" : ""} in files not committed yet`)));
    out.push("");
    for (const f of check) out.push(...block(f, c.yellow));
  }
  if (ok.length) {
    out.push(`${c.green("✔")} ${ok.length} key${ok.length > 1 ? "s" : ""} only in gitignored local files ${c.dim("(fine: " + ok.map((f) => f.provider).join(", ") + ")")}`);
    out.push("");
  }

  if (risky.length) {
    out.push(c.bold("What to do"));
    out.push(`  1. Rotate each key above. Deleting the file does not help: assume a pushed key is already copied.`);
    out.push(`  2. Put the new key in your deploy platform's secrets, not in code or a NEXT_PUBLIC_/VITE_ variable.`);
    out.push(`  3. Set a monthly spend limit on every AI provider, so one leak cannot drain your account.`);
    out.push("");
  }
  out.push(c.dim(`Get alerts on new leaks and spend spikes, and rotate everywhere in one pass: ${c.cyan("https://leakmoat.com/?ref=cli")}`));
  out.push("");
  return out.join("\n");
}

function bestExposure(f) {
  const rank = worst(f);
  return Object.keys(EXPOSURE_RANK).find((k) => EXPOSURE_RANK[k] === rank);
}

function block(f, color) {
  const exp = bestExposure(f);
  const lines = [`  ${color("●")} ${c.bold(f.provider)}  ${c.dim(f.masked)}`];
  const locs = [...f.locations].sort((a, b) => EXPOSURE_RANK[a.exposure] - EXPOSURE_RANK[b.exposure]);
  for (const l of locs.slice(0, 5)) lines.push(`      ${where(l)}`);
  if (locs.length > 5) lines.push(c.dim(`      and ${locs.length - 5} more places`));
  lines.push(c.dim(`      Why: ${EXPLAIN[exp]}.`));
  lines.push(f.rotateUrl ? `      Rotate: ${c.cyan(f.rotateUrl)}` : `      Fix: ${f.rotateHint}.`);
  lines.push("");
  return lines;
}

export function toJSON(result) {
  return JSON.stringify(
    {
      root: result.root,
      stats: result.stats,
      atRisk: result.findings.filter((f) => AT_RISK.has(bestExposure(f))).length,
      findings: result.findings.map((f) => ({ ...f, exposure: bestExposure(f) })),
    },
    null,
    2,
  );
}

export function hasRisk(result) {
  return result.findings.some((f) => AT_RISK.has(bestExposure(f)));
}
