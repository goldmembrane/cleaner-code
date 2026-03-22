import { Finding, Scanner } from "../types";
import { getLineAndColumn, getSnippet, codePointStr } from "../utils";

const BIDI_CHARS: Record<number, string> = {
  0x202a: "Left-to-Right Embedding (LRE)",
  0x202b: "Right-to-Left Embedding (RLE)",
  0x202c: "Pop Directional Formatting (PDF)",
  0x202d: "Left-to-Right Override (LRO)",
  0x202e: "Right-to-Left Override (RLO)",
  0x2066: "Left-to-Right Isolate (LRI)",
  0x2067: "Right-to-Left Isolate (RLI)",
  0x2068: "First Strong Isolate (FSI)",
  0x2069: "Pop Directional Isolate (PDI)",
};

export class BidiScanner implements Scanner {
  name = "bidi-control";

  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    // Track open/close pairs for unterminated sequences
    let openCount = 0;
    const openPositions: number[] = [];

    for (let i = 0; i < content.length; i++) {
      const cp = content.codePointAt(i)!;
      const charName = BIDI_CHARS[cp];
      if (!charName) continue;

      // Track embedding/override/isolate nesting
      if (
        cp === 0x202a || cp === 0x202b || cp === 0x202d ||
        cp === 0x202e || cp === 0x2066 || cp === 0x2067 ||
        cp === 0x2068
      ) {
        openCount++;
        openPositions.push(i);
      } else if (cp === 0x202c || cp === 0x2069) {
        openCount = Math.max(0, openCount - 1);
        if (openPositions.length > 0) openPositions.pop();
      }

      const { line, column } = getLineAndColumn(content, i);
      const snippet = getSnippet(content, line);

      // RLO and LRO are especially dangerous (Trojan Source core)
      const isTrojanSource = cp === 0x202e || cp === 0x202d;

      findings.push({
        category: "bidi-control",
        severity: isTrojanSource ? "critical" : "high",
        file: filePath,
        line,
        column,
        message: `BiDi control character detected: ${charName}${isTrojanSource ? " — Trojan Source attack vector" : ""}`,
        snippet,
        codePoint: codePointStr(String.fromCodePoint(cp)),
        recommendation: isTrojanSource
          ? `CRITICAL: This is a Trojan Source attack vector (CVE-2021-42574). The ${charName} character makes code appear differently to humans vs compilers. Remove immediately.`
          : `Remove the BiDi control character "${charName}". It can alter visual code rendering and hide malicious logic.`,
      });
    }

    // Check for unterminated BiDi sequences (extra dangerous)
    if (openCount > 0) {
      for (const pos of openPositions) {
        const { line, column } = getLineAndColumn(content, pos);
        const cp = content.codePointAt(pos)!;
        findings.push({
          category: "bidi-control",
          severity: "critical",
          file: filePath,
          line,
          column,
          message: `Unterminated BiDi control sequence — missing PDF/PDI closing character`,
          snippet: getSnippet(content, line),
          codePoint: codePointStr(String.fromCodePoint(cp)),
          recommendation:
            "Unterminated BiDi sequences affect all subsequent code rendering. This is a strong indicator of a Trojan Source attack.",
        });
      }
    }

    return findings;
  }
}
