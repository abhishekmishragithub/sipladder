import { chromium } from "@playwright/test";
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { pcap, udp, message } from "../src/sample";
mkdirSync("docs/screenshots", { recursive: true });
const browser = await chromium.launch({
  ...(process.env.CHROME_PATH
    ? { executablePath: process.env.CHROME_PATH }
    : {}),
  headless: true,
  args: [
    "--no-sandbox",
    ...(process.env.SINGLE_PROCESS
      ? ["--single-process", "--in-process-gpu", "--no-zygote"]
      : []),
  ],
});
const context = await browser.newContext({
  viewport: { width: 1440, height: 1080 },
  colorScheme: "dark",
  permissions: ["clipboard-read", "clipboard-write"],
});
const page = await context.newPage();
const errors: string[] = [];
page.on("pageerror", (e) => errors.push(e.message));
await page.goto("http://127.0.0.1:4173/");
await page.waitForLoadState("networkidle");
await page.screenshot({ path: "docs/screenshots/01-drop.png", fullPage: true });
const requests: string[] = [];
page.on("request", (r) => {
  requests.push(r.url());
});
// Real File + DataTransfer drop, not the demo button.
const buffer = Array.from(
  new Uint8Array((await import("../src/sample")).demoCapture()),
);
await page.evaluate((bytes) => {
  const dt = new DataTransfer();
  dt.items.add(new File([new Uint8Array(bytes)], "answered.pcap"));
  document.dispatchEvent(
    new DragEvent("drop", {
      dataTransfer: dt,
      bubbles: true,
      cancelable: true,
    }),
  );
}, buffer);
await page.locator("#status").filter({ hasText: "Capture ready." }).waitFor();
assert.equal(await page.locator("#ladder [data-message]").count(), 7);
await page.screenshot({
  path: "docs/screenshots/02-ladder.png",
  fullPage: true,
});
await page.locator('[data-message="3"]').click();
await page
  .locator("#detail-content pre")
  .getByText("PCMU/8000", { exact: false })
  .waitFor();
await page.locator("#ladder").focus();
await page.keyboard.press("ArrowDown");
assert.equal(
  await page.locator('[data-message="4"]').getAttribute("aria-pressed"),
  "true",
);
await page.screenshot({
  path: "docs/screenshots/03-detail.png",
  fullPage: true,
});
await page.getByRole("button", { name: "Text table", exact: true }).click();
assert.equal(await page.locator("#table tbody tr").count(), 7);
await page.getByRole("button", { name: "Copy sanitized ladder" }).click();
const copied = await page.evaluate(() => navigator.clipboard.readText());
assert.match(copied, /endpoint 1 -> endpoint 2/);
assert.ok(!copied.includes("alice"));
assert.ok(!copied.includes("192.0.2"));
// Verify CSP independently of the UI by attempting fetch and an exfiltration image.
const csp = await page.evaluate(async () => {
  let fetched = false;
  try {
    await fetch("/privacy-probe");
    fetched = true;
  } catch {}
  const img = new Image();
  const imageBlocked = await new Promise<boolean>((resolve) => {
    img.onload = () => resolve(false);
    img.onerror = () => resolve(true);
    img.src = "https://example.com/pixel";
  });
  return { fetched, imageBlocked };
});
assert.equal(csp.fetched, false);
assert.equal(csp.imageBlocked, true);
const workerBlocked = await page.evaluate(
  () =>
    new Promise<boolean>((resolve, reject) => {
      const url = URL.createObjectURL(
        new Blob(
          [
            `fetch('${location.origin}/privacy-probe-worker').then(()=>postMessage(false)).catch(()=>postMessage(true));`,
          ],
          { type: "text/javascript" },
        ),
      );
      const w = new Worker(url);
      w.onmessage = (e) => {
        resolve(e.data);
        w.terminate();
        URL.revokeObjectURL(url);
      };
      w.onerror = () => reject(Error("CSP probe worker failed to load"));
    }),
);
assert.equal(workerBlocked, true);

assert.equal(
  requests.filter(
    (url) =>
      !url.startsWith("https://example.com") &&
      !url.startsWith("blob:") &&
      !url.includes("/privacy-probe"),
  ).length,
  0,
);
await page.getByRole("button", { name: "Clear capture", exact: true }).click();
assert.equal(await page.locator("#ladder [data-message]").count(), 0);
await page.locator("#intro").waitFor({ state: "visible" });
await page.locator("#file").setInputFiles({
  name: "broken.pcap",
  mimeType: "application/octet-stream",
  buffer: Buffer.from("invalid"),
});
await page.locator("#error").waitFor({ state: "visible" });
assert.match(await page.locator("#error").innerText(), /Not a supported/);
const big = pcap(
  Array(16000).fill(
    udp(message("INVITE sip:bob@example.test SIP/2.0", "1 INVITE")),
  ),
);
await page.locator("#file").setInputFiles({
  name: "large.pcap",
  mimeType: "application/octet-stream",
  buffer: Buffer.from(big),
});
await page.locator("#status").filter({ hasText: "Capture ready." }).waitFor();
assert.equal(await page.locator("#ladder [data-message]").count(), 100);
await page.getByRole("button", { name: "Next →", exact: true }).click();
assert.equal(await page.locator('[data-message="100"]').count(), 1);
// A replacement file with no SIP must not expose the previous inspector or ladder.
await page.locator("#file").setInputFiles({
  name: "empty.pcap",
  mimeType: "application/octet-stream",
  buffer: Buffer.from(pcap([])),
});
await page
  .locator("#status")
  .filter({ hasText: "No complete SIP messages" })
  .waitFor();
assert.equal(await page.locator("#ladder [data-message]").count(), 0);
assert.equal(await page.locator("#detail-content").innerText(), "");

await page.getByRole("button", { name: "Switch color theme" }).click();
assert.equal(await page.locator("html").getAttribute("data-theme"), "light");
await page.setViewportSize({ width: 390, height: 844 });
await page.getByRole("button", { name: "Clear capture", exact: true }).click();
await page.screenshot({
  path: "docs/screenshots/04-mobile.png",
  fullPage: true,
});
assert.equal(
  await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
  false,
);
assert.deepEqual(errors, []);
console.log(
  "Browser checks passed: drop, worker, detail, keyboard, table, clipboard redaction, CSP, clear, invalid file, 4MB capture pagination, theme and mobile.",
);
await browser.close();
