import { Finding, Scanner } from "../types";
import { getLineAndColumn, getSnippet, codePointStr } from "../utils";

// Map of commonly confused characters: non-Latin → Latin lookalike
const HOMOGLYPH_MAP: Record<number, { latin: string; script: string }> = {
  // Cyrillic → Latin
  0x0410: { latin: "A", script: "Cyrillic" },
  0x0412: { latin: "B", script: "Cyrillic" },
  0x0421: { latin: "C", script: "Cyrillic" },
  0x0415: { latin: "E", script: "Cyrillic" },
  0x041d: { latin: "H", script: "Cyrillic" },
  0x041a: { latin: "K", script: "Cyrillic" },
  0x041c: { latin: "M", script: "Cyrillic" },
  0x041e: { latin: "O", script: "Cyrillic" },
  0x0420: { latin: "P", script: "Cyrillic" },
  0x0422: { latin: "T", script: "Cyrillic" },
  0x0425: { latin: "X", script: "Cyrillic" },
  0x0430: { latin: "a", script: "Cyrillic" },
  0x0441: { latin: "c", script: "Cyrillic" },
  0x0435: { latin: "e", script: "Cyrillic" },
  0x043e: { latin: "o", script: "Cyrillic" },
  0x0440: { latin: "p", script: "Cyrillic" },
  0x0455: { latin: "s", script: "Cyrillic" },
  0x0445: { latin: "x", script: "Cyrillic" },
  0x0443: { latin: "y", script: "Cyrillic" },
  // Greek → Latin
  0x0391: { latin: "A", script: "Greek" },
  0x0392: { latin: "B", script: "Greek" },
  0x0395: { latin: "E", script: "Greek" },
  0x0397: { latin: "H", script: "Greek" },
  0x0399: { latin: "I", script: "Greek" },
  0x039a: { latin: "K", script: "Greek" },
  0x039c: { latin: "M", script: "Greek" },
  0x039d: { latin: "N", script: "Greek" },
  0x039f: { latin: "O", script: "Greek" },
  0x03a1: { latin: "P", script: "Greek" },
  0x03a4: { latin: "T", script: "Greek" },
  0x03a5: { latin: "Y", script: "Greek" },
  0x03a7: { latin: "X", script: "Greek" },
  0x03b1: { latin: "a", script: "Greek" },  // alpha
  0x03bf: { latin: "o", script: "Greek" },  // omicron
  0x03c1: { latin: "p", script: "Greek" },  // rho
  // Fullwidth Latin
  0xff21: { latin: "A", script: "Fullwidth" },
  0xff22: { latin: "B", script: "Fullwidth" },
  0xff23: { latin: "C", script: "Fullwidth" },
  0xff41: { latin: "a", script: "Fullwidth" },
  0xff42: { latin: "b", script: "Fullwidth" },
  0xff43: { latin: "c", script: "Fullwidth" },
  // Common confusables
  0x0131: { latin: "i", script: "Latin Extended (dotless i)" },
  0x0269: { latin: "i", script: "IPA" },
  0x2010: { latin: "-", script: "Punctuation (Hyphen)" },
  0x2011: { latin: "-", script: "Punctuation (Non-Breaking Hyphen)" },
  0x2012: { latin: "-", script: "Punctuation (Figure Dash)" },
  0x2013: { latin: "-", script: "Punctuation (En Dash)" },
  0x2014: { latin: "-", script: "Punctuation (Em Dash)" },
  0xff0d: { latin: "-", script: "Fullwidth Hyphen-Minus" },
};

// Check if a character is a basic Latin identifier char
function isLatinIdent(cp: number): boolean {
  return (
    (cp >= 0x41 && cp <= 0x5a) || // A-Z
    (cp >= 0x61 && cp <= 0x7a) || // a-z
    (cp >= 0x30 && cp <= 0x39) || // 0-9
    cp === 0x5f                    // _
  );
}

export class HomoglyphScanner implements Scanner {
  name = "homoglyph";

  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split("\n");

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      // Simple check: skip lines that look like string contents or comments
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) {
        continue;
      }

      // Extract identifier-like sequences and check for mixed scripts
      let identStart = -1;
      let hasLatin = false;
      let hasNonLatin = false;
      const mixedPositions: Array<{ pos: number; cp: number }> = [];

      for (let i = 0; i <= line.length; i++) {
        const cp = i < line.length ? line.codePointAt(i)! : 0;

        const isIdent = cp !== 0 && (isLatinIdent(cp) || HOMOGLYPH_MAP[cp] !== undefined);

        if (isIdent && identStart === -1) {
          identStart = i;
          hasLatin = false;
          hasNonLatin = false;
          mixedPositions.length = 0;
        }

        if (isIdent) {
          if (isLatinIdent(cp)) {
            hasLatin = true;
          } else if (HOMOGLYPH_MAP[cp]) {
            hasNonLatin = true;
            mixedPositions.push({ pos: i, cp });
          }
        }

        if (!isIdent && identStart !== -1) {
          // End of identifier
          if (hasLatin && hasNonLatin) {
            const ident = line.slice(identStart, i);
            for (const { pos, cp: mcp } of mixedPositions) {
              const info = HOMOGLYPH_MAP[mcp]!;
              const globalIdx = content.split("\n").slice(0, lineIdx).join("\n").length + (lineIdx > 0 ? 1 : 0) + pos;
              findings.push({
                category: "homoglyph",
                severity: "high",
                file: filePath,
                line: lineIdx + 1,
                column: pos + 1,
                message: `Homoglyph detected in identifier "${ident}": ${info.script} '${String.fromCodePoint(mcp)}' looks like Latin '${info.latin}' (CVE-2021-42694)`,
                snippet: getSnippet(content, lineIdx + 1),
                codePoint: codePointStr(String.fromCodePoint(mcp)),
                recommendation: `Replace the ${info.script} character (${codePointStr(String.fromCodePoint(mcp))}) with its Latin equivalent '${info.latin}'. Mixed-script identifiers are a homoglyph attack indicator.`,
              });
            }
          }
          identStart = -1;
        }

        // Handle surrogate pairs
        if (cp > 0xffff) i++;
      }
    }

    return findings;
  }
}
