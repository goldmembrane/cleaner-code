import { Finding, Severity, ScanResult, ScanSummary } from "./types";
import * as fs from "fs";
import * as path from "path";

export function getLineAndColumn(
  content: string,
  index: number
): { line: number; column: number } {
  const before = content.slice(0, index);
  const line = before.split("\n").length;
  const lastNewline = before.lastIndexOf("\n");
  const column = index - lastNewline;
  return { line, column };
}

export function getSnippet(content: string, line: number): string {
  const lines = content.split("\n");
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 1);
  return lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1} | ${l}`)
    .join("\n");
}

export function codePointStr(char: string): string {
  const cp = char.codePointAt(0);
  if (cp === undefined) return "U+????";
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

export function collectFiles(
  dirPath: string,
  extensions?: string[]
): string[] {
  const results: string[] = [];
  const defaultExts = [
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".rb", ".go", ".java", ".c", ".cpp", ".h",
    ".cs", ".rs", ".swift", ".kt", ".php",
    ".json", ".yaml", ".yml", ".toml",
    ".md", ".txt", ".html", ".css", ".scss",
    ".sh", ".bash", ".zsh", ".ps1",
  ];
  const exts = extensions ?? defaultExts;

  function walk(dir: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (
          entry.name === "node_modules" ||
          entry.name === ".git" ||
          entry.name === "dist" ||
          entry.name === "__pycache__" ||
          entry.name === ".next" ||
          entry.name === "vendor"
        ) {
          continue;
        }
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (exts.includes(ext)) {
          results.push(fullPath);
        }
      }
    }
  }

  walk(dirPath);
  return results;
}

export function buildSummary(results: ScanResult[]): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const byCategory: Record<string, number> = {};
  let totalFindings = 0;

  for (const result of results) {
    for (const f of result.findings) {
      totalFindings++;
      bySeverity[f.severity]++;
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    }
  }

  return {
    totalFiles: results.length,
    totalFindings,
    bySeverity,
    byCategory,
    files: results.filter((r) => r.findings.length > 0),
  };
}

export function formatSummary(summary: ScanSummary): string {
  const lines: string[] = [];
  lines.push(`## Scan Summary`);
  lines.push(`- Files scanned: ${summary.totalFiles}`);
  lines.push(`- Total findings: ${summary.totalFindings}`);
  lines.push("");

  if (summary.totalFindings === 0) {
    lines.push("No threats detected.");
    return lines.join("\n");
  }

  lines.push("### By Severity");
  for (const [sev, count] of Object.entries(summary.bySeverity)) {
    if (count > 0) {
      const icon =
        sev === "critical" ? "🔴" :
        sev === "high" ? "🟠" :
        sev === "medium" ? "🟡" :
        sev === "low" ? "🔵" : "⚪";
      lines.push(`  ${icon} ${sev}: ${count}`);
    }
  }

  lines.push("");
  lines.push("### By Category");
  for (const [cat, count] of Object.entries(summary.byCategory)) {
    lines.push(`  - ${cat}: ${count}`);
  }

  lines.push("");
  lines.push("### Details");
  for (const result of summary.files) {
    lines.push(`\n**${result.file}** (${result.findings.length} findings)`);
    for (const f of result.findings) {
      lines.push(`  - [${f.severity.toUpperCase()}] Line ${f.line}: ${f.message}`);
      if (f.codePoint) {
        lines.push(`    Code point: ${f.codePoint}`);
      }
      lines.push(`    → ${f.recommendation}`);
    }
  }

  return lines.join("\n");
}
