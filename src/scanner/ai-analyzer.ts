import { Finding, Scanner } from "../types";
import { getSnippet } from "../utils";
import * as path from "path";
import * as fs from "fs";
import { spawn, ChildProcess } from "child_process";

let ort: typeof import("onnxruntime-node") | null = null;
let session: any = null;
let tokenizerProcess: ChildProcess | null = null;
let tokenizerReady = false;
let pendingRequests: Array<{
  resolve: (value: { input_ids: number[]; attention_mask: number[] }) => void;
  reject: (err: Error) => void;
}> = [];
let responseBuffer = "";

const MODEL_DIR = path.join(__dirname, "..", "..", "ml", "models", "onnx");
const MODEL_PATH = path.join(MODEL_DIR, "model.onnx");
const TOKENIZER_SCRIPT = path.join(
  __dirname, "..", "..", "ml", "scripts", "tokenize_server.py"
);
const MAX_LENGTH = 256;

function startTokenizer(): Promise<void> {
  return new Promise((resolve, reject) => {
    tokenizerProcess = spawn("python", [TOKENIZER_SCRIPT, MODEL_DIR], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    tokenizerProcess.stdout!.on("data", (data: Buffer) => {
      responseBuffer += data.toString();
      const lines = responseBuffer.split("\n");
      responseBuffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);

          if (parsed.status === "ready") {
            tokenizerReady = true;
            resolve();
            continue;
          }

          if (pendingRequests.length > 0) {
            const req = pendingRequests.shift()!;
            if (parsed.error) {
              req.reject(new Error(parsed.error));
            } else {
              req.resolve(parsed);
            }
          }
        } catch (e) {
          // Skip unparseable lines
        }
      }
    });

    tokenizerProcess.stderr!.on("data", (data: Buffer) => {
      // Log tokenizer warnings but don't fail
      const msg = data.toString().trim();
      if (msg && !msg.includes("FutureWarning") && !msg.includes("tokenizers")) {
        console.error("[tokenizer]", msg);
      }
    });

    tokenizerProcess.on("error", (err) => {
      console.error("Tokenizer process error:", err);
      reject(err);
    });

    tokenizerProcess.on("close", (code) => {
      tokenizerReady = false;
      if (code !== 0) {
        console.error(`Tokenizer exited with code ${code}`);
      }
      // Reject pending requests
      for (const req of pendingRequests) {
        req.reject(new Error("Tokenizer process exited"));
      }
      pendingRequests = [];
    });

    // Timeout
    setTimeout(() => {
      if (!tokenizerReady) {
        reject(new Error("Tokenizer startup timeout"));
      }
    }, 30000);
  });
}

function tokenize(text: string): Promise<{ input_ids: number[]; attention_mask: number[] }> {
  return new Promise((resolve, reject) => {
    if (!tokenizerProcess || !tokenizerReady) {
      reject(new Error("Tokenizer not ready"));
      return;
    }

    pendingRequests.push({ resolve, reject });
    tokenizerProcess.stdin!.write(JSON.stringify({ text }) + "\n");
  });
}

async function ensureModel(): Promise<boolean> {
  if (session && tokenizerReady) return true;

  try {
    if (!fs.existsSync(MODEL_PATH)) {
      console.error(`ONNX model not found at ${MODEL_PATH}`);
      return false;
    }

    // Start tokenizer
    if (!tokenizerReady) {
      await startTokenizer();
    }

    // Load ONNX model
    if (!session) {
      ort = require("onnxruntime-node");
      session = await ort!.InferenceSession.create(MODEL_PATH, {
        executionProviders: ["cpu"],
      });
    }

    console.error("AI analyzer model loaded successfully");
    return true;
  } catch (err) {
    console.error("Failed to load AI model:", err);
    return false;
  }
}

function softmax(logits: number[]): number[] {
  const maxLogit = Math.max(...logits);
  const exps = logits.map((l) => Math.exp(l - maxLogit));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map((e) => e / sum);
}

export async function analyzeCode(
  code: string
): Promise<{ label: "malicious" | "benign"; confidence: number } | null> {
  const ready = await ensureModel();
  if (!ready || !session || !ort) return null;

  try {
    const { input_ids, attention_mask } = await tokenize(code);

    const inputIdsTensor = new ort.Tensor(
      "int64",
      BigInt64Array.from(input_ids.map(BigInt)),
      [1, MAX_LENGTH]
    );
    const attentionMaskTensor = new ort.Tensor(
      "int64",
      BigInt64Array.from(attention_mask.map(BigInt)),
      [1, MAX_LENGTH]
    );

    const results = await session.run({
      input_ids: inputIdsTensor,
      attention_mask: attentionMaskTensor,
    });

    const logits = Array.from(results.logits.data as Float32Array);
    const probs = softmax(logits);
    const predictedClass = probs[1] > probs[0] ? 1 : 0;
    const confidence = Math.max(probs[0], probs[1]);

    return {
      label: predictedClass === 1 ? "malicious" : "benign",
      confidence,
    };
  } catch (err) {
    console.error("AI analysis error:", err);
    return null;
  }
}

function splitIntoChunks(content: string): Array<{ code: string; startLine: number }> {
  const lines = content.split("\n");
  const chunks: Array<{ code: string; startLine: number }> = [];

  const windowSize = 10;
  const stride = 5;

  for (let i = 0; i < lines.length; i += stride) {
    const chunk = lines.slice(i, i + windowSize).join("\n");
    if (chunk.trim().length > 10) {
      chunks.push({ code: chunk, startLine: i + 1 });
    }
  }

  if (lines.length <= 50) {
    chunks.unshift({ code: content, startLine: 1 });
  }

  return chunks;
}

export class AIAnalyzerScanner implements Scanner {
  name = "ai-analyzer";

  scan(content: string, filePath: string): Finding[] {
    return [];
  }

  async scanAsync(content: string, filePath: string): Promise<Finding[]> {
    const ready = await ensureModel();
    if (!ready) return [];

    const findings: Finding[] = [];
    const chunks = splitIntoChunks(content);

    for (const chunk of chunks) {
      const result = await analyzeCode(chunk.code);
      if (!result) continue;

      if (result.label === "malicious" && result.confidence > 0.7) {
        findings.push({
          category: "obfuscation",
          severity:
            result.confidence > 0.95
              ? "critical"
              : result.confidence > 0.85
              ? "high"
              : "medium",
          file: filePath,
          line: chunk.startLine,
          column: 1,
          message: `AI analysis: code classified as malicious (confidence: ${(result.confidence * 100).toFixed(1)}%)`,
          snippet: getSnippet(content, chunk.startLine),
          recommendation:
            "The AI model detected patterns consistent with malicious code. Review this section carefully for obfuscation, data exfiltration, or unauthorized access patterns.",
        });
      }
    }

    // Deduplicate overlapping findings
    const deduped: Finding[] = [];
    for (const f of findings) {
      const existing = deduped.find(
        (d) => Math.abs(d.line - f.line) < 5 && d.file === f.file
      );
      if (!existing) {
        deduped.push(f);
      }
    }

    return deduped;
  }
}

// Cleanup on process exit
process.on("exit", () => {
  if (tokenizerProcess) {
    tokenizerProcess.kill();
  }
});
