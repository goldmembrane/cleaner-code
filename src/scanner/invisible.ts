import { Finding, Scanner } from "../types";
import { getLineAndColumn, getSnippet, codePointStr } from "../utils";

const INVISIBLE_CHARS: Record<number, string> = {
  0x200b: "Zero-Width Space",
  0x200c: "Zero-Width Non-Joiner",
  0x200d: "Zero-Width Joiner",
  0x200e: "Left-to-Right Mark",
  0x200f: "Right-to-Left Mark",
  0x00ad: "Soft Hyphen",
  0x034f: "Combining Grapheme Joiner",
  0x061c: "Arabic Letter Mark",
  0xfeff: "Zero-Width No-Break Space (BOM)",
  0x2060: "Word Joiner",
  0x2061: "Function Application",
  0x2062: "Invisible Times",
  0x2063: "Invisible Separator",
  0x2064: "Invisible Plus",
  0x180e: "Mongolian Vowel Separator",
  0x00a0: "Non-Breaking Space",
  0x2000: "En Quad",
  0x2001: "Em Quad",
  0x2002: "En Space",
  0x2003: "Em Space",
  0x2004: "Three-Per-Em Space",
  0x2005: "Four-Per-Em Space",
  0x2006: "Six-Per-Em Space",
  0x2007: "Figure Space",
  0x2008: "Punctuation Space",
  0x2009: "Thin Space",
  0x200a: "Hair Space",
  0x202f: "Narrow No-Break Space",
  0x205f: "Medium Mathematical Space",
  0x3000: "Ideographic Space",
};

// Characters that are OK at certain positions (e.g., BOM at start)
const BOM = 0xfeff;
// NBSP in strings/comments is often acceptable
const NBSP = 0x00a0;

export class InvisibleCharScanner implements Scanner {
  name = "invisible-chars";

  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    for (let i = 0; i < content.length; i++) {
      const cp = content.codePointAt(i)!;

      // Skip BOM at the very start of file
      if (cp === BOM && i === 0) continue;

      const charName = INVISIBLE_CHARS[cp];
      if (!charName) continue;

      // NBSP: only flag if it's outside string literals (heuristic)
      if (cp === NBSP) {
        const { line } = getLineAndColumn(content, i);
        const lineText = content.split("\n")[line - 1] || "";
        // Simple heuristic: skip if inside quotes
        const before = lineText.slice(0, i - content.lastIndexOf("\n", i) - 1);
        const singleQuotes = (before.match(/'/g) || []).length;
        const doubleQuotes = (before.match(/"/g) || []).length;
        if (singleQuotes % 2 === 1 || doubleQuotes % 2 === 1) continue;
      }

      const { line, column } = getLineAndColumn(content, i);
      const snippet = getSnippet(content, line);

      findings.push({
        category: "invisible-chars",
        severity: cp === NBSP ? "medium" : "high",
        file: filePath,
        line,
        column,
        message: `Invisible character detected: ${charName}`,
        snippet,
        codePoint: codePointStr(String.fromCodePoint(cp)),
        recommendation: `Remove the invisible character "${charName}" (${codePointStr(String.fromCodePoint(cp))}). It may hide malicious content or alter code behavior.`,
      });
    }

    return findings;
  }
}
