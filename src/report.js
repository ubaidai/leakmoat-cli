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
  staged: "in the changes you are about to commit",
  unpushed: "in a commit that has not been pushed yet",
  new: "added by the commits in this change",
  committed: "committed in the repo right now; anyone with repo access can read it",
  public: "uses a public env prefix, so it ships to every visitor's browser",
  history: "deleted from the files but still in git history; every clone has it",
  untracked: "not committed yet; make sure this file is in .gitignore",
  local: "local file, gitignored",
};

export const AT_RISK = new Set(["staged", "unpushed", "new", "committed", "public", "history"]);

function where(l) {
  if (l.exposure === "unpushed" || l.exposure === "new") return `${l.file}${l.line ? c.dim(`:${l.line}`) : ""} ${c.dim(`(commit ${l.commit})`)}`;
  if (l.exposure === "history") return `${l.file} ${c.dim(`(commit ${l.commit}, ${l.date})`)}`;
  return `${l.file}${l.line ? c.dim(`:${l.line}`) : ""}`;
}

export function printReport(result) {
  if (result.stats.mode) return printHookReport(result);
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

/** Short output for pre-commit / pre-push hooks: what is blocked and exactly how to fix it. */
function printHookReport(result) {
  const { findings, stats } = result;
  const mode = stats.mode; // staged | push | range
  const scope =
    mode === "staged"
      ? `${stats.files} staged file${stats.files === 1 ? "" : "s"}`
      : mode === "range"
        ? `${stats.commits} commit${stats.commits === 1 ? "" : "s"} since ${stats.since}`
        : `${stats.commits} unpushed commit${stats.commits === 1 ? "" : "s"}`;
  const out = [];
  if (findings.length === 0) {
    out.push(`${c.orange("leakmoat")} ${c.green("✔")} ${c.dim(`no secrets in ${scope}`)}`);
    return out.join("\n");
  }
  const action = mode === "staged" ? "commit blocked" : mode === "push" ? "push blocked" : "check failed";
  out.push("");
  out.push(c.red(c.bold(`✖ leakmoat: ${action}, ${findings.length} secret${findings.length > 1 ? "s" : ""} in ${scope}`)));
  out.push("");
  for (const f of findings) {
    out.push(`  ${c.red("●")} ${c.bold(f.provider)}  ${c.dim(f.masked)}`);
    for (const l of f.locations.slice(0, 5)) out.push(`      ${where(l)}`);
    if (f.locations.length > 5) out.push(c.dim(`      and ${f.locations.length - 5} more places`));
    if (mode === "range") out.push(f.rotateUrl ? `      Rotate: ${c.cyan(f.rotateUrl)}` : `      Fix: ${f.rotateHint}.`);
  }
  out.push("");
  if (mode === "range") {
    // In CI the commit is already on GitHub: treat the key as exposed.
    out.push(c.bold("These commits are already pushed, so treat each key as exposed:"));
    out.push("  1. Rotate it now with the link above.");
    out.push("  2. Remove it from the branch before merging, and load it from an env var or secret store instead.");
    out.push("  3. False positive? Add a `leakmoat:ignore` comment on that line.");
  } else {
    out.push(c.bold("Good news: it has not left your machine, so there is nothing to rotate yet."));
    if (mode === "staged") {
      out.push("  1. Move the value to an env var or secret store, then `git add` the file again.");
    } else {
      out.push("  1. Remove the value, then rewrite the unpushed commit (`git commit --amend`, or `git rebase -i` for older ones).");
    }
    out.push("  2. False positive? Add a `leakmoat:ignore` comment on that line.");
    out.push(c.dim(`  Emergency only: \`git ${mode === "staged" ? "commit" : "push"} --no-verify\` skips this check.`));
  }
  out.push("");
  return out.join("\n");
}

// GitHub Actions workflow commands: one inline annotation per location, shown on the PR diff.
const ghEscape = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const ghProp = (s) => ghEscape(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

export function toAnnotations(result) {
  const lines = [];
  for (const f of result.findings) {
    const exp = bestExposure(f);
    if (!AT_RISK.has(exp)) continue;
    const fix = f.rotateUrl ? `Rotate it: ${f.rotateUrl}` : `${f.rotateHint}.`;
    for (const l of f.locations) {
      if (!AT_RISK.has(l.exposure)) continue;
      const props = [`file=${ghProp(l.file)}`];
      if (l.line) props.push(`line=${l.line}`);
      props.push(`title=${ghProp(`Leaked ${f.provider} secret`)}`);
      lines.push(`::error ${props.join(",")}::${ghEscape(`${f.masked} is ${EXPLAIN[l.exposure]}. ${fix}`)}`);
    }
  }
  return lines.join("\n");
}

/** Markdown for the GitHub Actions job summary. Masked values only. */
export function toMarkdown(result) {
  const risky = result.findings.filter((f) => AT_RISK.has(bestExposure(f)));
  const s = result.stats;
  const scope = s.mode === "range" ? `${s.commits} commits since \`${s.since}\`` : s.mode ? `${s.files} files` : `${s.files} files and ${s.commits} commits`;
  const md = ["## leakmoat", ""];
  if (risky.length === 0) {
    md.push(`✅ No exposed secrets in ${scope}.`);
  } else {
    md.push(`❌ **${risky.length} exposed secret${risky.length > 1 ? "s" : ""}** in ${scope}.`, "");
    md.push("| Secret | Where | Fix |", "|---|---|---|");
    for (const f of risky) {
      const l = f.locations[0];
      const where = `\`${l.file}${l.line ? `:${l.line}` : ""}\`${l.commit ? ` (${l.commit})` : ""}${f.locations.length > 1 ? ` +${f.locations.length - 1} more` : ""}`;
      const fix = f.rotateUrl ? `[Rotate](${f.rotateUrl})` : f.rotateHint;
      md.push(`| ${f.provider} \`${f.masked}\` | ${where} | ${fix} |`);
    }
    md.push("", "Remove each value from the code, load it from a secret store, and rotate it. False positive? Add a `leakmoat:ignore` comment on that line.");
  }
  md.push("", "<sub>Scanned by [leakmoat](https://github.com/ubaidai/leakmoat-cli). Nothing left the runner.</sub>", "");
  return md.join("\n");
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
