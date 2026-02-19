/**
 * page_crawl_analyze.ts
 *
 * Install:
 *   npm i axios jsdom @mozilla/readability openai
 *   npm i -D ts-node typescript @types/node
 *
 * Run:
 *   OPENAI_API_KEY=... npx ts-node page_crawl_analyze.ts "https://example.com"
 *
 * Optional (if you need cookies):
 *   COOKIES='name=value; name2=value2' OPENAI_API_KEY=... npx ts-node page_crawl_analyze.ts "https://..."
 */

import axios from "axios";
import { JSDOM } from "jsdom";
import { Readability } from "@mozilla/readability";
import OpenAI from "openai";

type CrawlOutput = {
  url: string;
  fetchedAt: string;
  http: {
    finalUrl: string;
    status?: number | undefined;
    contentType?: string;
  };
  page: {
    title: string;
    header?: string | undefined; // if Confluence selector exists
    extractedText: string;
    extractedTextChars: number;
  };
  crawlNext: {
    totalLinksFound: number;
    links: Array<{
      url: string;
      text?: string | undefined;
      rel?: string | undefined;
      sameOrigin: boolean;
      kind: string; //"anchor" | "canonical" | "other";
    }>;
  };
  analysis: {
    brief: string;
    contentTags: string[];
    qualityScore: number; // 0-100
    readabilityScore: number; // 0-100
    valueScore: number; // 0-100
    issues: string[];
    vectorRecords: Array<{
      id: string;
      text: string;
      metadata: {
        sourceUrl: string;
        title: string;
        tags: string[];
        sectionHint?: string | undefined;
      };
    }>;
  };
};

function nowIso(): string {
  return new Date().toISOString();
}

function normalizeWhitespace(s: string): string {
  return s.replace(/\u00a0/g, " ").replace(/\s+/g, " ").trim();
}

function shouldSkipHref(href: string): boolean {
  const h = href.trim().toLowerCase();
  return (
    h === "" ||
    h.startsWith("#") ||
    h.startsWith("mailto:") ||
    h.startsWith("tel:") ||
    h.startsWith("javascript:") ||
    h.startsWith("data:")
  );
}

function chunkText(text: string, maxChars = 1200): string[] {
  const t = text.trim();
  if (!t) return [];
  const chunks: string[] = [];
  let i = 0;

  while (i < t.length) {
    const end = Math.min(i + maxChars, t.length);
    let cut = end;

    // prefer sentence/space boundary
    if (end < t.length) {
      const window = t.slice(i, end);
      const last = Math.max(window.lastIndexOf(". "), window.lastIndexOf(" "));
      if (last > Math.floor(maxChars * 0.5)) cut = i + last + 1;
    }

    chunks.push(t.slice(i, cut).trim());
    i = cut;
  }
  return chunks.filter(Boolean);
}

function getCookieHeader(): string | undefined {
  const c = process.env.COOKIES?.trim();
  return c ? c : undefined;
}

async function fetchHtml(url: string): Promise<{ html: string; finalUrl: string; status?: number | undefined; contentType?: string  | undefined}> {
  const cookieHeader = getCookieHeader();

  const resp = await axios.get(url, {
    timeout: 25000,
    maxRedirects: 5,
    responseType: "text",
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; PageCrawlAnalyze/1.0)",
      Accept: "text/html,application/xhtml+xml",
      ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    },
    validateStatus: (s) => s >= 200 && s < 400,
  });

  const finalUrl =
    (resp.request?.res?.responseUrl as string | undefined) ?? url;

  const contentType = (resp.headers?.["content-type"] as string | undefined) ?? undefined;

  return { html: String(resp.data), finalUrl, status: resp.status, contentType };
}

function extractLinks(baseUrl: string, html: string): CrawlOutput["crawlNext"] {
  const base = new URL(baseUrl);
  const dom = new JSDOM(html, { url: baseUrl });
  const doc = dom.window.document;

  const links: CrawlOutput["crawlNext"]["links"] = [];
  const seen = new Set<string>();

  // Canonical (if present) is often useful for dedupe
  const canonical = doc.querySelector('link[rel="canonical"][href]')?.getAttribute("href");
  if (canonical && !shouldSkipHref(canonical)) {
    try {
      const u = new URL(canonical, base);
      u.hash = "";
      const s = u.toString();
      if (!seen.has(s)) {
        seen.add(s);
        links.push({
          url: s,
          sameOrigin: u.origin === base.origin,
          kind: "canonical",
        });
      }
    } catch { /* ignore */ }
  }

  // All anchors
  const anchors = Array.from(doc.querySelectorAll("a[href]"));
  for (const a of anchors) {
    const href = a.getAttribute("href") ?? "";
    if (shouldSkipHref(href)) continue;

    let u: URL;
    try {
      u = new URL(href, base);
    } catch {
      continue;
    }
    u.hash = "";
    const s = u.toString();
    if (seen.has(s)) continue;
    seen.add(s);

    const text = normalizeWhitespace(a.textContent ?? "");
    const rel = a.getAttribute("rel") ?? undefined;

    const link = {
      url: s,
      text: text,
      rel: rel || undefined,
      sameOrigin: u.origin === base.origin,
      kind: "anchor",
    }

    links.push(link);
  }

  return { totalLinksFound: links.length, links };
}

/**
 * Extracts "reader sensible" text:
 * - If Confluence selectors exist: header + ak-renderer-wrapper content
 * - Else: Readability main article
 * - Else: body text fallback
 */
function extractContent(baseUrl: string, html: string): { title: string; header?: string | undefined; text: string } {
  const dom = new JSDOM(html, { url: baseUrl });
  const doc = dom.window.document;

  const title = normalizeWhitespace(doc.title || "") || "Untitled";

  const headerEl = doc.querySelector('div[data-testid="content-header-container"]');
  const contentEl = doc.querySelector("div.ak-renderer-wrapper");

  if (contentEl) {
    const header = normalizeWhitespace(headerEl?.textContent ?? "") || undefined;
    const text = normalizeWhitespace(contentEl.textContent ?? "");
    return { title, header, text };
  }

  // Readability fallback
  try {
    const reader = new Readability(doc);
    const article = reader.parse();
    const text = normalizeWhitespace(article?.textContent ?? "");
    if (text) return { title: normalizeWhitespace(article?.title ?? "") || title, text };
  } catch {
    // ignore
  }

  // Body fallback
  const bodyText = normalizeWhitespace(doc.body?.textContent ?? "");
  return { title, text: bodyText };
}

function buildAnalysisPrompt(input: {
  url: string;
  title: string;
  header?: string | undefined;
  text: string;
}): string {
  const headerLine = input.header ? `Header: ${input.header}\n` : "";
  return [
    "You are an information quality rater and content tagger for a web-crawl pipeline.",
    "Your job: produce a reader-sensible brief, tags, quality/readability/value scores, issues, and vector-db-ready records.",
    "",
    "Rules:",
    "- Ignore any navigation/menu/UI fragments if present.",
    "- Focus only on content that would make sense to a reader.",
    "- If the text is messy, say so in issues and reduce scores.",
    "- Tags should be short, consistent, and useful for retrieval.",
    "- Vector records should be self-contained chunks suitable for embedding.",
    "",
    `URL: ${input.url}`,
    `Title: ${input.title}`,
    headerLine.trimEnd(),
    "",
    "CONTENT:",
    input.text.slice(0, 20000), // cap to keep requests reasonable
  ]
    .filter((l) => l !== "")
    .join("\n");
}

async function analyzeWithOpenAI(params: {
  url: string;
  title: string;
  header?: string;
  text: string;
  chunks: string[];
}): Promise<CrawlOutput["analysis"]> {
  const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

  // We ask the model to return JSON that matches our schema (Structured Outputs). :contentReference[oaicite:1]{index=1}
  const schema = {
    name: "page_analysis",
    schema: {
      type: "object",
      additionalProperties: false,
      properties: {
        brief: { type: "string" },
        contentTags: { type: "array", items: { type: "string" }, minItems: 1 },
        qualityScore: { type: "integer", minimum: 0, maximum: 100 },
        readabilityScore: { type: "integer", minimum: 0, maximum: 100 },
        valueScore: { type: "integer", minimum: 0, maximum: 100 },
        issues: { type: "array", items: { type: "string" } },
        vectorRecords: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            properties: {
              id: { type: "string" },
              text: { type: "string" },
              metadata: {
                type: "object",
                additionalProperties: false,
                properties: {
                  sourceUrl: { type: "string" },
                  title: { type: "string" },
                  tags: { type: "array", items: { type: "string" } },
                  sectionHint: { type: "string" },
                },
                required: ["sourceUrl", "title", "tags"],
              },
            },
            required: ["id", "text", "metadata"],
          },
        },
      },
      required: ["brief", "contentTags", "qualityScore", "readabilityScore", "valueScore", "issues", "vectorRecords"],
    },
  };

  const prompt = buildAnalysisPrompt({
    url: params.url,
    title: params.title,
    header: params.header,
    text: params.text,
  });

  // Give the model the chunks we plan to embed; ask it to pick/clean/label them into vectorRecords.
  const chunkList = params.chunks
    .slice(0, 25)
    .map((c, i) => `CHUNK ${i + 1}:\n${c}`)
    .join("\n\n");

  const input = `${prompt}\n\nCANDIDATE CHUNKS (for vector records):\n${chunkList}`;

  const resp = await client.responses.create({
    model: "gpt-5.2", // choose the model you prefer
    input,
    text: {
      format: {
        schema: schema,
        type: "json_schema",
      },
    },
  });

  // openai-node provides output_text convenience, but we requested structured JSON,
  // so parse from output_text (it will be JSON). :contentReference[oaicite:2]{index=2}
  const raw = (resp.output_text ?? "").trim();
  if (!raw) throw new Error("OpenAI response had no output_text");
  return JSON.parse(raw) as CrawlOutput["analysis"];
}

async function main(): Promise<void> {
  const startUrl = process.argv[2];
  if (!startUrl) {
    console.error("Usage: npx ts-node page_crawl_analyze.ts <url>");
    process.exit(1);
  }
  if (!process.env.OPENAI_API_KEY) {
    console.error("Missing OPENAI_API_KEY environment variable.");
    process.exit(1);
  }

  // 1) Fetch
  const fetchedAt = nowIso();
  const fetched = await fetchHtml(startUrl);

  // 2) Links to crawl next
  const crawlNext = extractLinks(fetched.finalUrl, fetched.html);

  // 3) Content extraction
  const extracted = extractContent(fetched.finalUrl, fetched.html);
  const extractedText = extracted.text;

  // 4) Prepare candidate chunks for embedding / downstream retrieval
  const chunks = chunkText(extractedText, 1200);

  // 5) OpenAI analysis (brief, tags, scores, vector-ready records)
  const analysis = await analyzeWithOpenAI({
    url: fetched.finalUrl,
    title: extracted.title,
    header: extracted.header,
    text: extractedText,
    chunks,
  });

  const output: CrawlOutput = {
    url: startUrl,
    fetchedAt,
    http: {
      finalUrl: fetched.finalUrl,
      status: fetched.status,
      contentType: fetched.contentType,
    },
    page: {
      title: extracted.title,
      header: extracted.header,
      extractedText,
      extractedTextChars: extractedText.length,
    },
    crawlNext,
    analysis,
  };

  // Print a single JSON object suitable for piping into a file or another system
  console.log(JSON.stringify(output, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
