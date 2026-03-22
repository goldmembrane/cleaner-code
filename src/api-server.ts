#!/usr/bin/env node

/**
 * AI Analysis API Server for Cloud Run.
 * Exposes the CodeBERT model as a REST API with API key authentication.
 */

import * as http from "http";
import { analyzeCode, AIAnalyzerScanner } from "./scanner/ai-analyzer";

const PORT = parseInt(process.env.PORT || "8080", 10);
const API_VALIDATE_URL =
  process.env.API_VALIDATE_URL || "https://cleanercode.dev/api/validate-key";
const USAGE_URL =
  process.env.USAGE_URL || "https://cleanercode.dev/api/usage";

// Simple in-memory rate limit cache (per-key, resets on restart)
const rateLimitCache = new Map<string, { count: number; resetAt: number }>();

function parseBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}

function json(res: http.ServerResponse, status: number, data: any) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  res.end(JSON.stringify(data));
}

async function validateApiKey(
  apiKey: string
): Promise<{ valid: boolean; plan?: string; remaining?: number }> {
  try {
    const resp = await fetch(API_VALIDATE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apiKey }),
    });
    return await resp.json();
  } catch {
    // If validation service is down, allow with warning
    console.error("API validation service unreachable");
    return { valid: true, plan: "unknown", remaining: -1 };
  }
}

async function recordUsage(apiKey: string, action: string) {
  try {
    await fetch(USAGE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apiKey, action }),
    });
  } catch {
    console.error("Usage tracking failed");
  }
}

function checkRateLimit(apiKey: string, limit: number): boolean {
  const now = Date.now();
  const entry = rateLimitCache.get(apiKey);

  if (!entry || now > entry.resetAt) {
    rateLimitCache.set(apiKey, { count: 1, resetAt: now + 60_000 });
    return true;
  }

  if (entry.count >= limit) return false;
  entry.count++;
  return true;
}

const server = http.createServer(async (req, res) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    json(res, 204, null);
    return;
  }

  // Health check
  if (req.url === "/health" && req.method === "GET") {
    json(res, 200, { status: "ok", model: "codebert-v1" });
    return;
  }

  // POST /api/analyze
  if (req.url === "/api/analyze" && req.method === "POST") {
    try {
      // Auth
      const authHeader = req.headers.authorization;
      const apiKey = authHeader?.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;

      if (!apiKey) {
        json(res, 401, { error: "Missing API key. Set Authorization: Bearer <key>" });
        return;
      }

      // Validate key
      const keyInfo = await validateApiKey(apiKey);
      if (!keyInfo.valid) {
        json(res, 403, { error: "Invalid or expired API key" });
        return;
      }

      // Check remaining quota
      if (keyInfo.remaining !== undefined && keyInfo.remaining <= 0) {
        json(res, 429, {
          error: "Monthly AI analysis quota exceeded",
          plan: keyInfo.plan,
          upgrade: "https://cleanercode.dev/#pricing",
        });
        return;
      }

      // Rate limit: 30 requests per minute per key
      if (!checkRateLimit(apiKey, 30)) {
        json(res, 429, { error: "Rate limit exceeded. Max 30 requests/minute." });
        return;
      }

      // Parse body
      const body = await parseBody(req);
      const { code, chunks } = JSON.parse(body);

      if (!code && !chunks) {
        json(res, 400, { error: "Missing 'code' or 'chunks' field" });
        return;
      }

      // Single code analysis
      if (code) {
        const result = await analyzeCode(code);
        if (!result) {
          json(res, 500, { error: "Model inference failed" });
          return;
        }

        // Record usage
        await recordUsage(apiKey, "ai_analyze");

        json(res, 200, {
          result,
          plan: keyInfo.plan,
          remaining: keyInfo.remaining !== undefined ? keyInfo.remaining - 1 : undefined,
        });
        return;
      }

      // Batch analysis
      if (Array.isArray(chunks)) {
        const results = [];
        for (const chunk of chunks.slice(0, 20)) {
          // Max 20 chunks per request
          const result = await analyzeCode(chunk.code || chunk);
          results.push({
            code: (chunk.code || chunk).slice(0, 100) + "...",
            startLine: chunk.startLine || 0,
            ...result,
          });
        }

        await recordUsage(apiKey, "ai_analyze_batch");

        json(res, 200, {
          results,
          analyzed: results.length,
          plan: keyInfo.plan,
          remaining: keyInfo.remaining !== undefined ? keyInfo.remaining - 1 : undefined,
        });
        return;
      }
    } catch (err: any) {
      console.error("Analysis error:", err);
      json(res, 500, { error: err.message });
      return;
    }
  }

  // 404
  json(res, 404, { error: "Not found" });
});

server.listen(PORT, () => {
  console.log(`cleaner-code AI API server running on port ${PORT}`);
});
