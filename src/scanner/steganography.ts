import { Finding, Scanner } from "../types";
import { getLineAndColumn, getSnippet, codePointStr } from "../utils";

// Glassworm attack uses Variation Selectors and PUA characters
// to encode invisible payloads in source code

// Variation Selectors: U+FE00–U+FE0F
const VS_START = 0xfe00;
const VS_END = 0xfe0f;

// Variation Selectors Supplement: U+E0100–U+E01EF
const VSS_START = 0xe0100;
const VSS_END = 0xe01ef;

// Tags block: U+E0001–U+E007F (used for language tags, abused for steganography)
const TAG_START = 0xe0001;
const TAG_END = 0xe007f;

// Private Use Area ranges
const PUA_RANGES: Array<[number, number, string]> = [
  [0xe000, 0xf8ff, "Basic PUA"],
  [0xf0000, 0xffffd, "Supplementary PUA-A"],
  [0x100000, 0x10fffd, "Supplementary PUA-B"],
];

// Threshold: a few variation selectors are normal (emoji modifiers)
// but clusters are suspicious
const VS_CLUSTER_THRESHOLD = 3;

export class SteganographyScanner implements Scanner {
  name = "steganography";

  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    let vsCluster: Array<{ index: number; cp: number }> = [];
    let puaCount = 0;
    const puaPositions: Array<{ index: number; cp: number; range: string }> = [];
    let tagCount = 0;
    const tagPositions: Array<{ index: number; cp: number }> = [];

    for (let i = 0; i < content.length; i++) {
      const cp = content.codePointAt(i)!;

      // Check Variation Selectors
      if ((cp >= VS_START && cp <= VS_END) || (cp >= VSS_START && cp <= VSS_END)) {
        vsCluster.push({ index: i, cp });
      } else {
        if (vsCluster.length >= VS_CLUSTER_THRESHOLD) {
          const first = vsCluster[0];
          const { line, column } = getLineAndColumn(content, first.index);
          findings.push({
            category: "steganography",
            severity: "critical",
            file: filePath,
            line,
            column,
            message: `Variation Selector cluster (${vsCluster.length} chars) — Glassworm-style steganographic payload`,
            snippet: getSnippet(content, line),
            codePoint: vsCluster.map((v) => codePointStr(String.fromCodePoint(v.cp))).slice(0, 5).join(", ") + (vsCluster.length > 5 ? "..." : ""),
            recommendation:
              "A cluster of Variation Selector characters is a strong indicator of a Glassworm steganographic attack. These invisible characters encode a hidden payload that gets decoded and eval'd. Remove the entire sequence immediately.",
          });
        }
        vsCluster = [];
      }

      // Check Tags block
      if (cp >= TAG_START && cp <= TAG_END) {
        tagCount++;
        tagPositions.push({ index: i, cp });
      }

      // Check PUA ranges
      for (const [start, end, name] of PUA_RANGES) {
        if (cp >= start && cp <= end) {
          puaCount++;
          puaPositions.push({ index: i, cp, range: name });
          break;
        }
      }

      // Handle surrogate pairs
      if (cp > 0xffff) i++;
    }

    // Flush remaining cluster
    if (vsCluster.length >= VS_CLUSTER_THRESHOLD) {
      const first = vsCluster[0];
      const { line, column } = getLineAndColumn(content, first.index);
      findings.push({
        category: "steganography",
        severity: "critical",
        file: filePath,
        line,
        column,
        message: `Variation Selector cluster (${vsCluster.length} chars) — Glassworm-style steganographic payload`,
        snippet: getSnippet(content, line),
        codePoint: vsCluster.map((v) => codePointStr(String.fromCodePoint(v.cp))).slice(0, 5).join(", "),
        recommendation:
          "A cluster of Variation Selector characters is a strong indicator of a Glassworm steganographic attack. Remove immediately.",
      });
    }

    // Report Tags block usage (should never appear in source code)
    if (tagCount > 0) {
      const first = tagPositions[0];
      const { line, column } = getLineAndColumn(content, first.index);
      findings.push({
        category: "steganography",
        severity: "critical",
        file: filePath,
        line,
        column,
        message: `Unicode Tags block characters detected (${tagCount} chars) — possible steganographic encoding`,
        snippet: getSnippet(content, line),
        codePoint: codePointStr(String.fromCodePoint(first.cp)),
        recommendation:
          "Unicode Tags block (U+E0001–U+E007F) characters have no legitimate use in source code. They can encode hidden ASCII text invisibly. Remove immediately.",
      });
    }

    // Report excessive PUA usage
    if (puaCount > 5) {
      const first = puaPositions[0];
      const { line, column } = getLineAndColumn(content, first.index);
      findings.push({
        category: "steganography",
        severity: "high",
        file: filePath,
        line,
        column,
        message: `Excessive Private Use Area characters (${puaCount} chars in ${first.range}) — possible hidden payload`,
        snippet: getSnippet(content, line),
        codePoint: codePointStr(String.fromCodePoint(first.cp)),
        recommendation:
          "Large numbers of PUA characters in source code may indicate steganographically encoded payloads. Review the file for hidden data.",
      });
    }

    return findings;
  }
}
