# CodeSafer (cleaner-code)

> **AI code security scanner as a Model Context Protocol (MCP) server.**
> Detects hidden threats in AI-generated code that traditional linters miss.

[![npm](https://img.shields.io/badge/mcp-server-blue)](https://modelcontextprotocol.io)
[![license: ISC](https://img.shields.io/badge/license-ISC-green)](#license)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

**Website:** [codesafer.org](https://codesafer.org/) &nbsp;·&nbsp; **MCP Clients:** Claude Code, Cursor, VS Code + Copilot, Cline

---

## Why CodeSafer?

AI coding assistants generate code fast — but who's checking it for hidden threats?

Recent supply-chain attacks show that malicious code can hide in ways human reviewers and traditional linters routinely miss:

- **Invisible Unicode characters** injected into identifiers (30+ variants)
- **BiDi / Trojan Source** attacks that reorder how code is displayed vs. executed (CVE-2021-42574)
- **Homoglyphs** — Cyrillic characters masquerading as Latin (CVE-2021-42694)
- **Glassworm-style Unicode steganography** hiding payloads in whitespace
- **Rules file backdoors** planted in `.cursorrules`, `CLAUDE.md`, and other AI config files
- **Typosquatted dependencies** in `package.json`
- **Obfuscation patterns** — `eval` + base64, reverse shells, packed payloads

CodeSafer scans for all of these before the code runs on your machine.

---

## How it works

CodeSafer runs as a local MCP server. Your AI client (Claude Code, Cursor, etc.) calls its tools when reviewing or generating code, and findings are returned inline.

**Hybrid detection:**

1. **8 static analysis scanners** — deterministic rules for known attack categories (fast, zero false-negatives on the patterns they cover).
2. **CodeBERT deep analysis** — transformer model classifies code chunks as malicious/benign with confidence scores. Catches obfuscated or novel patterns that static rules miss.

Nothing leaves your machine. The AI analysis runs locally against a tokenizer server.

---

## Features

| Capability | Details |
|---|---|
| Invisible character detection | 30+ Unicode variants including Zero-Width Space, Mongolian Vowel Separator |
| BiDi / Trojan Source | Full CVE-2021-42574 coverage |
| Homoglyph detection | Cyrillic/Greek/Latin confusables (CVE-2021-42694) |
| Unicode steganography | Glassworm-style whitespace payloads |
| Rules file backdoors | Scans `.cursorrules`, `CLAUDE.md`, `.claude/`, Cursor rules |
| Dependency scanning | Typosquatting + suspicious install scripts in `package.json` |
| Obfuscation detection | `eval` + base64, reverse shells, packed payloads |
| AI deep analysis | CodeBERT transformer classifier with confidence scores |
| MCP native | 6 MCP tools, stdio transport |
| Local-first | No code uploaded — runs entirely on your machine |

---

## MCP Tools

CodeSafer exposes six tools to your MCP client:

| Tool | Purpose |
|---|---|
| `scan_file` | Scan a single file for hidden malicious code patterns |
| `scan_directory` | Recursively scan a directory across all source files |
| `scan_rules_file` | Scan an AI configuration/rules file for prompt injection and Rules File Backdoor attacks |
| `check_dependencies` | Check `package.json` for typosquatting, suspicious install scripts, and dependency risks |
| `ai_analyze` | Deep AI analysis using the trained CodeBERT model (classifies chunks as malicious/benign with confidence) |
| `explain_finding` | Get detailed explanation of a specific threat category, with attack scenarios and remediation |

---

## Installation

### Prerequisites

- Node.js 18 or later
- An MCP-compatible client (Claude Code, Cursor, VS Code + Copilot, Cline)

### From source

```bash
git clone https://github.com/goldmembrane/cleaner-code.git
cd cleaner-code
npm install
npm run build
```

### Configure your MCP client

**Claude Code** (`~/.claude.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "codesafer": {
      "command": "node",
      "args": ["/absolute/path/to/cleaner-code/dist/index.js"]
    }
  }
}
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "codesafer": {
      "command": "node",
      "args": ["/absolute/path/to/cleaner-code/dist/index.js"]
    }
  }
}
```

Restart your client, and CodeSafer tools will appear in the tool picker.

---

## Usage

Once configured, ask your AI client things like:

- *"Scan this file for hidden security issues."*
- *"Check the dependencies in package.json for typosquatting."*
- *"Scan `.cursorrules` for a rules-file backdoor."*
- *"Run a deep AI analysis of `src/auth.ts`."*
- *"Explain what a Trojan Source attack is and how to fix the finding above."*

The client will call the appropriate MCP tool and return findings with severity, line numbers, and remediation guidance.

---

## Free tier & Plans

CodeSafer is free to use. Static analysis (`scan_file`, `scan_directory`, `scan_rules_file`, `check_dependencies`, `explain_finding`) has no limits.

AI deep analysis (`ai_analyze`) includes **10 free runs per session**. Paid plans for higher AI quotas are available at [codesafer.org](https://codesafer.org/).

---

## Detection categories

CodeSafer detects threats across **9 categories**:

1. **Invisible Unicode characters** — 30+ variants including Zero-Width Space, Zero-Width Joiner
2. **BiDi / Trojan Source attacks** — CVE-2021-42574
3. **Homoglyphs** — Cyrillic/Greek characters masquerading as Latin (CVE-2021-42694)
4. **Unicode steganography** — Glassworm patterns in whitespace
5. **Rules file backdoors** — malicious instructions in `.cursorrules`, `CLAUDE.md`, etc.
6. **Dependency risks** — typosquatting and suspicious install scripts
7. **Obfuscation patterns** — `eval` + base64, packed payloads, reverse shells
8. **Static analysis findings** — 8 deterministic scanners
9. **AI deep analysis** — CodeBERT transformer for novel and obfuscated threats

---

## Project structure

```
cleaner-code/
├── src/
│   ├── index.ts           # MCP server entry point
│   ├── api-server.ts      # Optional HTTP API server
│   ├── types.ts           # Scanner interfaces
│   ├── utils.ts           # File collection, summary formatting
│   └── scanner/
│       ├── invisible.ts       # Invisible Unicode scanner
│       ├── bidi.ts            # BiDi / Trojan Source scanner
│       ├── homoglyph.ts       # Homoglyph scanner
│       ├── encoding.ts        # Encoding / charset scanner
│       ├── obfuscation.ts     # Obfuscation pattern scanner
│       ├── steganography.ts   # Unicode steganography scanner
│       ├── rules-backdoor.ts  # Rules file backdoor scanner
│       ├── dependency.ts      # Dependency risk scanner
│       └── ai-analyzer.ts     # CodeBERT deep analyzer
├── ml/                    # ML model assets and tokenizer
├── functions/             # Cloud function deployments
├── deploy/                # Deployment manifests
└── web/                   # Landing page assets
```

---

## License

ISC — see the `LICENSE` file for details.

---

## Links

- **Website:** [codesafer.org](https://codesafer.org/)
- **Model Context Protocol:** [modelcontextprotocol.io](https://modelcontextprotocol.io/)
- **Report issues:** [GitHub Issues](https://github.com/goldmembrane/cleaner-code/issues)
