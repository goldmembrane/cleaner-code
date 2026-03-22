import { Finding, Scanner } from "../types";
import { getLineAndColumn, getSnippet } from "../utils";
import * as path from "path";

// Known AI rules/config file patterns
const RULES_FILE_PATTERNS = [
  ".cursorrules",
  ".cursorignore",
  "cursorrules",
  ".github/copilot-instructions.md",
  "copilot-instructions.md",
  ".aider",
  ".aider.conf.yml",
  "CLAUDE.md",
  ".claude/settings.json",
  ".claude/settings.local.json",
  ".windsurfrules",
  ".clinerules",
  ".cline",
  "rules.md",
  ".instructions",
];

// Suspicious prompt injection patterns in rules files
const INJECTION_PATTERNS: Array<{
  regex: RegExp;
  message: string;
  severity: "critical" | "high" | "medium";
  recommendation: string;
}> = [
  {
    regex: /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|guidelines?)/gi,
    message: "Prompt injection: attempts to override previous instructions",
    severity: "critical",
    recommendation:
      "This is a classic prompt injection pattern. It tries to make the AI disregard its safety rules. Remove this instruction.",
  },
  {
    regex: /(?:do\s+not|don't|never)\s+(?:mention|reveal|show|display|output|include)\s+(?:this|these)\s+(?:instructions?|rules?)/gi,
    message: "Prompt injection: attempts to hide its own existence",
    severity: "critical",
    recommendation:
      "Instructions that hide themselves are a hallmark of prompt injection attacks. This prevents users from knowing the AI is being manipulated.",
  },
  {
    regex: /(?:always|must)\s+(?:include|add|insert|inject)\s+(?:the\s+following|this)\s+(?:code|script|snippet)/gi,
    message: "Suspicious instruction: forces AI to always inject specific code",
    severity: "high",
    recommendation:
      "Instructions forcing the AI to always include specific code may be injecting backdoors into every generated file.",
  },
  {
    regex: /(?:whenever|every\s+time|always)\s+(?:generating|creating|writing)\s+(?:code|files?|scripts?).*?(?:include|add|prepend|append)/gi,
    message: "Suspicious instruction: injects code into every generation",
    severity: "high",
    recommendation:
      "This instruction modifies all AI-generated code, potentially adding backdoors or tracking scripts to every file.",
  },
  {
    regex: /(?:send|post|fetch|request|upload|exfiltrate|transmit)\s+(?:to|data|information|credentials|env|tokens?|keys?|secrets?)/gi,
    message: "Suspicious instruction: potential data exfiltration directive",
    severity: "critical",
    recommendation:
      "This instruction may direct the AI to write code that exfiltrates sensitive data. Review immediately.",
  },
  {
    regex: /(?:base64|encode|encrypt|obfuscate|hide)\s+(?:the|this|all)\s+(?:code|payload|script|content)/gi,
    message: "Suspicious instruction: directs AI to obfuscate output",
    severity: "high",
    recommendation:
      "Instructions to obfuscate generated code are suspicious — legitimate coding guidelines don't require hiding code.",
  },
  {
    regex: /(?:eval|exec|execute|run)\s*\(\s*(?:atob|decode|unescape)/gi,
    message: "Code execution pattern in rules file — possible payload",
    severity: "critical",
    recommendation:
      "Rules files should not contain executable code patterns. This may be a payload waiting to be injected.",
  },
  {
    regex: /(?:process\.env|environment\s+variables?|api[_\s]?keys?|credentials?|tokens?|secrets?).*?(?:log|print|console|send|fetch|post)/gi,
    message: "Suspicious instruction: references credential access with output/network",
    severity: "high",
    recommendation:
      "Rules that reference credentials alongside output/network operations may instruct the AI to leak secrets.",
  },
];

export class RulesBackdoorScanner implements Scanner {
  name = "rules-backdoor";

  isRulesFile(filePath: string): boolean {
    const basename = path.basename(filePath).toLowerCase();
    const relativePath = filePath.replace(/\\/g, "/");

    return RULES_FILE_PATTERNS.some((pattern) => {
      const normalizedPattern = pattern.toLowerCase();
      return (
        basename === normalizedPattern ||
        relativePath.toLowerCase().endsWith(normalizedPattern)
      );
    });
  }

  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    if (!this.isRulesFile(filePath)) {
      return findings;
    }

    // Check for prompt injection patterns
    for (const pattern of INJECTION_PATTERNS) {
      let match: RegExpExecArray | null;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

      while ((match = regex.exec(content)) !== null) {
        const { line, column } = getLineAndColumn(content, match.index);
        findings.push({
          category: "rules-backdoor",
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

    // Also run invisible char / bidi checks on rules files with elevated severity
    // (invisible chars in rules files are ALWAYS suspicious)
    for (let i = 0; i < content.length; i++) {
      const cp = content.codePointAt(i)!;
      if (
        cp === 0x200b || cp === 0x200c || cp === 0x200d ||
        cp === 0x200e || cp === 0x200f || cp === 0xfeff ||
        cp === 0x2060 || cp === 0x00ad ||
        (cp >= 0x202a && cp <= 0x202e) ||
        (cp >= 0x2066 && cp <= 0x2069)
      ) {
        const { line, column } = getLineAndColumn(content, i);
        findings.push({
          category: "rules-backdoor",
          severity: "critical",
          file: filePath,
          line,
          column,
          message: `Hidden unicode character in AI rules file — Rules File Backdoor attack indicator`,
          snippet: getSnippet(content, line),
          codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
          recommendation:
            "Invisible unicode characters in AI rules files are the primary vector for Rules File Backdoor attacks. They wrap malicious prompts that the AI reads but humans cannot see. Remove all invisible characters from this file.",
        });
      }
    }

    return findings;
  }
}
