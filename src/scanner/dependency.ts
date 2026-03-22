import { Finding, Scanner } from "../types";
import * as path from "path";

// Known popular packages — typosquatting targets
const POPULAR_PACKAGES: string[] = [
  "express", "react", "lodash", "axios", "moment", "chalk",
  "commander", "debug", "dotenv", "inquirer", "webpack",
  "babel", "eslint", "prettier", "typescript", "jest",
  "mocha", "chai", "underscore", "async", "request",
  "bluebird", "uuid", "glob", "minimist", "yargs",
  "colors", "semver", "mkdirp", "rimraf", "cross-env",
  "nodemon", "concurrently", "husky", "lint-staged",
  "tailwindcss", "postcss", "autoprefixer", "vite",
  "next", "nuxt", "vue", "angular", "svelte",
  "mongoose", "sequelize", "prisma", "typeorm",
  "socket.io", "cors", "helmet", "morgan",
  "jsonwebtoken", "bcrypt", "passport",
  "aws-sdk", "firebase", "stripe",
];

// Common typosquatting transformations
function generateTyposquatVariants(name: string): string[] {
  const variants: string[] = [];

  // Character swap: adjacent chars transposed
  for (let i = 0; i < name.length - 1; i++) {
    const swapped = name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2);
    if (swapped !== name) variants.push(swapped);
  }

  // Missing character
  for (let i = 0; i < name.length; i++) {
    variants.push(name.slice(0, i) + name.slice(i + 1));
  }

  // Double character
  for (let i = 0; i < name.length; i++) {
    variants.push(name.slice(0, i) + name[i] + name[i] + name.slice(i + 1));
  }

  // Common substitutions
  const subs: Record<string, string[]> = {
    a: ["@", "4"], e: ["3"], i: ["1", "l"], l: ["1", "i"],
    o: ["0"], s: ["5", "z"], t: ["7"], g: ["9", "q"],
  };
  for (let i = 0; i < name.length; i++) {
    const ch = name[i].toLowerCase();
    if (subs[ch]) {
      for (const sub of subs[ch]) {
        variants.push(name.slice(0, i) + sub + name.slice(i + 1));
      }
    }
  }

  // Hyphen/underscore confusion
  if (name.includes("-")) {
    variants.push(name.replace(/-/g, "_"));
    variants.push(name.replace(/-/g, ""));
  }
  if (name.includes("_")) {
    variants.push(name.replace(/_/g, "-"));
    variants.push(name.replace(/_/g, ""));
  }
  if (!name.includes("-") && !name.includes("_")) {
    // Try adding hyphens at common spots
    for (let i = 1; i < name.length; i++) {
      variants.push(name.slice(0, i) + "-" + name.slice(i));
    }
  }

  return variants;
}

// Suspicious install script patterns
const SUSPICIOUS_SCRIPTS: Array<{
  pattern: RegExp;
  message: string;
}> = [
  { pattern: /curl\s+.*?\|.*?(?:sh|bash)/i, message: "Pipe-to-shell in install script" },
  { pattern: /wget\s+.*?\|.*?(?:sh|bash)/i, message: "Pipe-to-shell in install script" },
  { pattern: /powershell.*?-(?:enc|EncodedCommand)/i, message: "Encoded PowerShell in install script" },
  { pattern: /eval\s*\(/, message: "eval() in install script" },
  { pattern: /child_process/, message: "child_process usage in install script" },
  { pattern: /process\.env.*(?:fetch|http|request)/i, message: "Env var exfiltration pattern in install script" },
];

// Build lookup of typosquat targets
const typosquatLookup = new Map<string, string>();
for (const pkg of POPULAR_PACKAGES) {
  for (const variant of generateTyposquatVariants(pkg)) {
    if (!POPULAR_PACKAGES.includes(variant)) {
      typosquatLookup.set(variant, pkg);
    }
  }
}

export class DependencyScanner implements Scanner {
  name = "suspicious-dependency";

  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const basename = path.basename(filePath);

    if (basename !== "package.json") {
      return findings;
    }

    let pkg: any;
    try {
      pkg = JSON.parse(content);
    } catch {
      return findings;
    }

    const allDeps: Record<string, string> = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.optionalDependencies || {}),
    };

    // Check for typosquatting
    for (const depName of Object.keys(allDeps)) {
      const target = typosquatLookup.get(depName);
      if (target) {
        findings.push({
          category: "suspicious-dependency",
          severity: "high",
          file: filePath,
          line: this.findDepLine(content, depName),
          column: 1,
          message: `Possible typosquatting: "${depName}" looks like popular package "${target}"`,
          snippet: `"${depName}": "${allDeps[depName]}"`,
          recommendation: `Verify this is the intended package. "${depName}" closely resembles the popular package "${target}" and may be a typosquatting attack.`,
        });
      }
    }

    // Check for suspicious install scripts
    const scripts = pkg.scripts || {};
    for (const [scriptName, scriptCmd] of Object.entries(scripts)) {
      if (
        scriptName === "preinstall" ||
        scriptName === "install" ||
        scriptName === "postinstall" ||
        scriptName === "preuninstall"
      ) {
        const cmd = String(scriptCmd);
        for (const { pattern, message } of SUSPICIOUS_SCRIPTS) {
          if (pattern.test(cmd)) {
            findings.push({
              category: "suspicious-dependency",
              severity: "high",
              file: filePath,
              line: this.findDepLine(content, scriptName),
              column: 1,
              message: `Suspicious install script (${scriptName}): ${message}`,
              snippet: `"${scriptName}": "${cmd}"`,
              recommendation: `Review the "${scriptName}" script carefully. Install hooks are a common vector for supply chain attacks.`,
            });
          }
        }

        // Flag any postinstall that runs a js file (common malware pattern)
        if (/node\s+\S+\.js/i.test(cmd)) {
          findings.push({
            category: "suspicious-dependency",
            severity: "medium",
            file: filePath,
            line: this.findDepLine(content, scriptName),
            column: 1,
            message: `Install script runs a JS file: "${cmd}" — review the target file`,
            snippet: `"${scriptName}": "${cmd}"`,
            recommendation: `Install scripts that execute JS files should be reviewed. Check the target file for malicious behavior.`,
          });
        }
      }
    }

    // Check for git:// URLs (can be hijacked)
    for (const [depName, depVersion] of Object.entries(allDeps)) {
      const ver = String(depVersion);
      if (ver.startsWith("git://")) {
        findings.push({
          category: "suspicious-dependency",
          severity: "medium",
          file: filePath,
          line: this.findDepLine(content, depName),
          column: 1,
          message: `Dependency "${depName}" uses insecure git:// protocol`,
          snippet: `"${depName}": "${ver}"`,
          recommendation: `Use https:// instead of git:// for dependency URLs. git:// is unencrypted and susceptible to MITM attacks.`,
        });
      }
      // Check for URL-based deps pointing to IPs
      if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(ver)) {
        findings.push({
          category: "suspicious-dependency",
          severity: "high",
          file: filePath,
          line: this.findDepLine(content, depName),
          column: 1,
          message: `Dependency "${depName}" references an IP address`,
          snippet: `"${depName}": "${ver}"`,
          recommendation: `Dependencies pointing to raw IP addresses are suspicious. Verify the source.`,
        });
      }
    }

    return findings;
  }

  private findDepLine(content: string, key: string): number {
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(`"${key}"`)) return i + 1;
    }
    return 1;
  }
}
