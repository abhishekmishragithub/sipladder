// WCAG relative luminance, including translucent grid/selection annotations.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const css = readFileSync("src/style.css", "utf8");
const rgb = (hex: string) =>
  [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
const luminance = (values: number[]) =>
  values.reduce((sum, value, i) => {
    const s = value / 255;
    return (
      sum +
      (s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4) *
        [0.2126, 0.7152, 0.0722][i]
    );
  }, 0);
const contrast = (a: number[], b: number[]) => {
  const [low, high] = [luminance(a), luminance(b)].sort((x, y) => x - y);
  return (high + 0.05) / (low + 0.05);
};
for (const [theme, selector] of [
  ["Paper", ":root {"],
  ["Blueprint", ':root[data-theme="dark"] {'],
]) {
  const block = css.slice(css.indexOf(selector)).split("}")[0];
  const tokens = Object.fromEntries(
    [...block.matchAll(/--([\w-]+): (#[\da-f]+);/g)].map((m) => [m[1], m[2]]),
  );
  const backgrounds = [tokens.bg, tokens.surface].map(rgb);
  for (const overlay of ["grid", "wash", "annotation"]) {
    const alpha = parseInt(tokens[overlay].slice(7, 9), 16) / 255;
    backgrounds.push(
      rgb(tokens[overlay]).map(
        (v, i) => v * alpha + rgb(tokens.bg)[i] * (1 - alpha),
      ),
    );
  }
  for (const name of [
    "ink",
    "muted",
    "accent",
    "good",
    "bad",
    "redirect",
    "line",
  ]) {
    const ratio = Math.min(
      ...backgrounds.map((bg) => contrast(rgb(tokens[name]), bg)),
    );
    assert.ok(
      ratio >= (name === "line" ? 3 : 4.5),
      `${theme} ${name}: ${ratio}`,
    );
    console.log(
      `${theme} / ${name}: ${ratio.toFixed(2)}:1 (minimum across paper, panel and overlays)`,
    );
  }
}
