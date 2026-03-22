import { Finding, Scanner } from "../types";
import { getLineAndColumn, getSnippet } from "../utils";

const PATTERNS: Array<{
  regex: RegExp;
  message: string;
  severity: "critical" | "high" | "medium";
  recommendation: string;
}> = [
  // eval with dynamic content
  {
    regex: /\beval\s*\(/g,
    message: "eval() call detected — dynamic code execution",
    severity: "high",
    recommendation:
      "eval() executes arbitrary code at runtime. If the argument comes from user input, encoded strings, or network, this is a critical risk. Replace with safe alternatives.",
  },
  // Function constructor
  {
    regex: /new\s+Function\s*\(/g,
    message: "new Function() — dynamic code generation",
    severity: "high",
    recommendation:
      "new Function() is equivalent to eval(). Review the arguments for dynamic/encoded content.",
  },
  // Base64 decode + eval pattern
  {
    regex: /(?:atob|Buffer\.from)\s*\([^)]*\).*?(?:eval|Function|\bexec\b)/gs,
    message: "Base64 decode chained with code execution — likely obfuscated payload",
    severity: "critical",
    recommendation:
      "Decoding base64 and executing it is a classic malware pattern. Decode the base64 content and review it immediately.",
  },
  // Reverse pattern: eval(atob(...))
  {
    regex: /\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(/g,
    message: "eval(atob()) — executing base64-decoded content",
    severity: "critical",
    recommendation:
      "This directly executes decoded base64 content. This is a strong indicator of hidden malicious code.",
  },
  // document.write with encoded content
  {
    regex: /document\.write\s*\(\s*(?:unescape|decodeURIComponent)\s*\(/g,
    message: "document.write with URL-decoded content — possible XSS payload",
    severity: "high",
    recommendation:
      "Writing decoded content to the DOM can execute hidden scripts. Review the encoded content.",
  },
  // setTimeout/setInterval with string argument
  {
    regex: /(?:setTimeout|setInterval)\s*\(\s*['"`]/g,
    message: "setTimeout/setInterval with string argument — implicit eval",
    severity: "medium",
    recommendation:
      "Passing a string to setTimeout/setInterval causes implicit eval(). Use a function reference instead.",
  },
  // Suspicious URL patterns
  {
    regex: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\/\S+/g,
    message: "URL with raw IP address — possible C2 or exfiltration endpoint",
    severity: "medium",
    recommendation:
      "URLs using raw IP addresses instead of domains may indicate command-and-control servers. Verify the destination.",
  },
  // Process/child_process spawn
  {
    regex: /(?:child_process|exec|execSync|spawn|spawnSync)\s*\(\s*(?:['"`]|`)/g,
    message: "Shell command execution detected",
    severity: "medium",
    recommendation:
      "Direct shell command execution can be dangerous if arguments are dynamic. Verify the command is safe and necessary.",
  },
  // Fetch/XMLHttpRequest to suspicious destinations
  {
    regex: /(?:fetch|XMLHttpRequest|axios|got|request)\s*\(\s*(?:['"`]\s*https?:\/\/\d)/g,
    message: "Network request to IP-based URL",
    severity: "medium",
    recommendation:
      "Network requests to raw IP addresses may indicate data exfiltration. Verify the endpoint.",
  },
  // PowerShell encoded command
  {
    regex: /powershell.*?-(?:enc|EncodedCommand)\s+[A-Za-z0-9+/=]{20,}/gi,
    message: "PowerShell encoded command — hidden script execution",
    severity: "critical",
    recommendation:
      "PowerShell encoded commands are frequently used to hide malicious scripts. Decode the base64 and review.",
  },
  // Crypto wallet addresses (potential C2 via blockchain)
  {
    regex: /(?:^|[^a-zA-Z0-9])(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90}|0x[0-9a-fA-F]{40})(?:[^a-zA-Z0-9]|$)/gm,
    message: "Cryptocurrency wallet address found — possible C2 channel (Glassworm pattern)",
    severity: "medium",
    recommendation:
      "Cryptocurrency addresses in source code may be used as C2 channels (as in the Glassworm attack). Verify this is intentional.",
  },
  // process.env exfiltration patterns
  {
    regex: /(?:fetch|axios|got|request|http\.request)\s*\([\s\S]{0,100}process\.env/g,
    message: "Environment variables being sent over network — possible credential exfiltration",
    severity: "critical",
    recommendation:
      "Sending process.env over the network is a strong indicator of credential theft. Review immediately.",
  },
];

export class ObfuscationScanner implements Scanner {
  name = "obfuscation";

  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    for (const pattern of PATTERNS) {
      let match: RegExpExecArray | null;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

      while ((match = regex.exec(content)) !== null) {
        const { line, column } = getLineAndColumn(content, match.index);
        findings.push({
          category: "obfuscation",
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
