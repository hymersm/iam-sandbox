/**
 * crawl_readable.ts
 *
 * Grabs a start page, follows all *same-origin* links found on the first page (1 hop),
 * extracts "readable" text (Mozilla Readability) from each page, and prints it in blocks.
 *
 * Install:
 *   npm i axios jsdom @mozilla/readability
 *
 * Run (Node 18+):
 *   npx ts-node crawl_readable.ts https://example.com
 * or compile:
 *   npm i -D typescript ts-node @types/node
 *   npx ts-node crawl_readable.ts https://example.com
 */

import axios from "axios";
import { JSDOM } from "jsdom";
import { Readability } from "@mozilla/readability";

type ExtractedDoc = {
  url: string;
  title: string;
  text: string;
};

function normalizeWhitespace(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

function chunkText(text: string, maxChars = 1800): string[] {
  const t = text.trim();
  if (!t) return [];

  const chunks: string[] = [];
  let start = 0;

  while (start < t.length) {
    const end = Math.min(start + maxChars, t.length);

    // Try to cut on a natural boundary.
    let cut = end;
    const window = t.slice(start, end);
    const lastBoundary =
      Math.max(window.lastIndexOf("\n\n"), window.lastIndexOf(". "), window.lastIndexOf(" "));

    if (lastBoundary > Math.floor(maxChars * 0.5) && end !== t.length) {
      cut = start + lastBoundary + 1;
    }

    chunks.push(t.slice(start, cut).trim());
    start = cut;
  }

  return chunks.filter(Boolean);
}

function isLikelyHtmlContentType(contentType: string | undefined): boolean {
  if (!contentType) return true; // be permissive; many servers omit it
  return contentType.toLowerCase().includes("text/html");
}

function shouldSkipLink(href: string): boolean {
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

function sameOrigin(a: URL, b: URL): boolean {
  return a.origin === b.origin;
}

function buildCookieHeader(cookies: Record<string, string>): string {
  return Object.entries(cookies)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

/**
 * Preferred: set COOKIES env var to a raw Cookie header string, e.g.
 *   COOKIES='JSESSIONID=...; tenant.session.token=...; atlassian.xsrf.token=...'
 */
function getCookieHeaderFromEnvOrMap(): string | undefined {
  const fromEnv = process.env.COOKIES?.trim();
  if (fromEnv) return fromEnv;

  // Fallback (local dev only): paste values here but DO NOT commit them.
  const cookies: Record<string, string> = {

  };

  const hasAny = Object.keys(cookies).length > 0;
  return hasAny ? buildCookieHeader(cookies) : undefined;
}

async function fetchHtml(url: string): Promise<{ html: string; finalUrl: string }> {
  const cookieHeader = getCookieHeaderFromEnvOrMap();
  
  const resp = await axios.get(url, {
    timeout: 20000,
    maxRedirects: 5,
    responseType: "text",
    headers: {
      // Some sites block empty/unknown user agents
      "User-Agent":
        "Mozilla/5.0 (compatible; ReadableCrawler/1.0; +https://example.invalid)",
      Accept: "text/html,application/xhtml+xml",
      ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    },
    validateStatus: (s) => s >= 200 && s < 400,
  });

  const contentType = resp.headers?.["content-type"] as string | undefined;
  if (!isLikelyHtmlContentType(contentType)) {
    throw new Error(`Non-HTML content-type: ${contentType ?? "unknown"}`);
  }

  const finalUrl =
    // axios in node keeps the final URL in request.res.responseUrl (most cases)
    (resp.request?.res?.responseUrl as string | undefined) ?? url;

  return { html: String(resp.data), finalUrl };
}

function extractSameOriginLinksFromFirstPage(startUrl: string, html: string): string[] {
  const base = new URL(startUrl);
  const dom = new JSDOM(html, { url: startUrl });
  const anchors = Array.from(dom.window.document.querySelectorAll("a[href]"));

  const out = new Set<string>();

  for (const a of anchors) {
    const raw = (a.getAttribute("href") ?? "").trim();
    if (shouldSkipLink(raw)) continue;

    let resolved: URL;
    try {
      resolved = new URL(raw, base);
    } catch {
      continue;
    }

    // Only follow same-origin links (avoid exploding into the whole web)
    if (!sameOrigin(base, resolved)) continue;

    // Drop URL fragments for dedupe
    resolved.hash = "";

    out.add(resolved.toString());
  }

  return [...out];
}

function extractReadableText(url: string, html: string): { title: string; text: string } {
  const dom = new JSDOM(html, { url });

  const reader = new Readability(dom.window.document);
  const article = reader.parse();

  if (!article?.textContent) {
    // Fallback: use body text
    const bodyText = dom.window.document.body?.textContent ?? "";
    return {
      title: dom.window.document.title || url,
      text: normalizeWhitespace(bodyText),
    };
  }

  return {
    title: article.title?.trim() || dom.window.document.title || url,
    text: normalizeWhitespace(article.textContent),
  };
}

function printDocBlocks(doc: ExtractedDoc, maxChars = 1800): void {
  const blocks = chunkText(doc.text, maxChars);

  console.log("\n" + "=".repeat(100));
  console.log(`URL:   ${doc.url}`);
  console.log(`TITLE: ${doc.title}`);
  console.log(`BLOCKS: ${blocks.length}`);
  console.log("=".repeat(100) + "\n");

  blocks.forEach((b, i) => {
    console.log(`--- [${i + 1}/${blocks.length}] ${doc.title} ---`);
    console.log(b);
    console.log(""); // spacer
  });
}

async function main(): Promise<void> {
  const startArg = process.argv[2];
  if (!startArg) {
    console.error("Usage: npx ts-node crawl_readable.ts <startUrl>");
    process.exitCode = 1;
    return;
  }

  let startUrl: string;
  try {
    startUrl = new URL(startArg).toString();
  } catch {
    console.error(`Invalid URL: ${startArg}`);
    process.exitCode = 1;
    return;
  }

  // 1) Fetch the start page
  const start = await fetchHtml(startUrl);
  const baseUrl = start.finalUrl;

  // 2) Extract same-origin links from ONLY the first page (1-hop crawl)
  const links = extractSameOriginLinksFromFirstPage(baseUrl, start.html);

  // Include the start page itself first
  const targets = [baseUrl, ...links.filter((u) => u !== baseUrl)];

  console.error(`Start: ${baseUrl}`);
  console.error(`Found ${links.length} same-origin links on the first page.`);
  console.error(`Will fetch ${targets.length} pages (start page + 1-hop links).`);

  // 3) Fetch each target and extract readable text
  for (const url of targets) {
    try {
      const { html, finalUrl } = await fetchHtml(url);
      const { title, text } = extractReadableText(finalUrl, html);

      // Skip empty-ish pages
      if (!text || text.length < 40) {
        console.error(`(skip) ${finalUrl} — too little text`);
        continue;
      }

      printDocBlocks({ url: finalUrl, title, text }, 1800);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`(error) ${url} — ${msg}`);
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
