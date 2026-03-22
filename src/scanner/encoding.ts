import { Finding, Scanner } from "../types";
import { getLineAndColumn, getSnippet } from "../utils";

// Patterns for suspicious encoding tricks
const PATTERNS: Array<{
  regex: RegExp;
  message: string;
  severity: "high" | "medium";
  recommendation: string;
}> = [
  {
    regex: /\\u\{0*(?:200[b-f]|202[a-e]|2066|2067|2068|2069|feff|00ad)\}/gi,
    message: "Unicode escape hiding invisible/BiDi character",
    severity: "high",
    recommendation:
      "This unicode escape decodes to a dangerous invisible or BiDi character. Remove it or replace with a visible equivalent.",
  },
  {
    regex: /\\u0*(?:200[bB-fF]|202[aA-eE]|206[6-9]|[fF][eE][fF][fF]|00[aA][dD])/g,
    message: "Unicode escape hiding invisible/BiDi character",
    severity: "high",
    recommendation:
      "This unicode escape decodes to a dangerous invisible or BiDi character. Remove it or replace with a visible equivalent.",
  },
  {
    regex: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){9,}/g,
    message: "Long hex escape sequence — possible encoded payload",
    severity: "medium",
    recommendation:
      "Excessively long hex escape sequences may hide obfuscated code. Decode and review the content.",
  },
  {
    regex: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}/g,
    message: "String.fromCharCode with many numeric args — dynamic string construction",
    severity: "high",
    recommendation:
      "Building strings from char codes is a common obfuscation technique. Decode the values and verify the resulting string.",
  },
  {
    regex: /String\.fromCodePoint\s*\(\s*(?:0x[0-9a-fA-F]+\s*,\s*){5,}/g,
    message: "String.fromCodePoint with many hex values — dynamic string construction",
    severity: "high",
    recommendation:
      "Building strings from code points is a common obfuscation technique. Decode and verify the resulting string.",
  },
  {
    regex: /(?:%[0-9a-fA-F]{2}){10,}/g,
    message: "Excessive percent-encoding — possible hidden payload",
    severity: "medium",
    recommendation:
      "Long percent-encoded strings may hide URLs, commands, or code. Decode and review.",
  },
  {
    regex: /\\u0{0,2}[0-9a-fA-F]{1,2}(?:\\u0{0,2}[0-9a-fA-F]{1,2}){9,}/g,
    message: "Chain of short unicode escapes — possible character-by-character obfuscation",
    severity: "medium",
    recommendation:
      "Many short unicode escapes in sequence may spell out hidden commands or URLs. Decode and review.",
  },
];

export class EncodingScanner implements Scanner {
  name = "suspicious-encoding";

  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    for (const pattern of PATTERNS) {
      let match: RegExpExecArray | null;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

      while ((match = regex.exec(content)) !== null) {
        const { line, column } = getLineAndColumn(content, match.index);
        findings.push({
          category: "suspicious-encoding",
          severity: pattern.severity,
          file: filePath,
          line,
          column,
          message: pattern.message,
          snippet: getSnippet(content, line),
          recommendation: pattern.recommendation,
        });
      }
    }

    return findings;
  }
}
