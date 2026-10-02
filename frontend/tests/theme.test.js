import test from "node:test";
import assert from "node:assert/strict";
import { defaults, normalizeTheme, foreground } from "../src/theme.js";

test("appearance rejects malformed persisted preferences", () => {
  assert.deepEqual(normalizeTheme(null), defaults);
  assert.deepEqual(
    normalizeTheme({
      mode: "unknown",
      primary: "url(x)",
      secondary: "#123",
      motion: "false",
    }),
    defaults,
  );
  assert.equal(
    normalizeTheme({ mode: "dark", primary: "#123456", motion: false }).motion,
    false,
  );
});
test("custom button colors retain readable foreground contrast", () => {
  const luminance = (hex) =>
    hex
      .slice(1)
      .match(/../g)
      .map((x) => parseInt(x, 16) / 255)
      .map((x) => (x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4))
      .reduce((sum, x, i) => sum + x * [0.2126, 0.7152, 0.0722][i], 0);
  for (const color of [
    "#000000",
    "#ffffff",
    "#007aff",
    "#7952e8",
    "#16846a",
    "#c85335",
    "#eeee00",
    "#777777",
  ]) {
    const a = luminance(color),
      b = luminance(foreground(color));
    assert.ok((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) >= 4.5, color);
  }
});
