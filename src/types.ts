export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category =
  | "invisible-chars"
  | "bidi-control"
  | "homoglyph"
  | "suspicious-encoding"
  | "obfuscation"
  | "steganography"
  | "rules-backdoor"
  | "slopsquatting"
  | "suspicious-dependency";

export interface Finding {
  category: Category;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  message: string;
  snippet: string;
  codePoint?: string;
  recommendation: string;
}

export interface ScanResult {
  file: string;
  findings: Finding[];
  scannedAt: string;
}

export interface ScanSummary {
  totalFiles: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  files: ScanResult[];
}

export interface Scanner {
  name: string;
  scan(content: string, filePath: string): Finding[];
}
