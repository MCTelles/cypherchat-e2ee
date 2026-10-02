export const defaults = {
  mode: "system",
  primary: "#007aff",
  secondary: "#34c7ad",
  motion: true,
};
export const presets = [
  { name: "Oceano", primary: "#007aff", secondary: "#34c7ad" },
  { name: "Íris", primary: "#7952e8", secondary: "#d28bda" },
  { name: "Floresta", primary: "#16846a", secondary: "#b1bd70" },
  { name: "Pôr do sol", primary: "#c85335", secondary: "#e9b65b" },
];
export function normalizeTheme(value = {}) {
  const color = (v, fallback) => (/^#[\da-f]{6}$/i.test(v) ? v : fallback);
  return {
    mode: ["light", "dark", "system"].includes(value?.mode)
      ? value.mode
      : defaults.mode,
    primary: color(value?.primary, defaults.primary),
    secondary: color(value?.secondary, defaults.secondary),
    motion: typeof value?.motion === "boolean" ? value.motion : true,
  };
}
export function foreground(hex) {
  const rgb = hex
    .slice(1)
    .match(/../g)
    .map((v) => parseInt(v, 16) / 255)
    .map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  const luminance = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
  return (luminance + 0.05) / 0.05 > 1.05 / (luminance + 0.05)
    ? "#000000"
    : "#ffffff";
}
export function readTheme() {
  try {
    return normalizeTheme(
      JSON.parse(localStorage.getItem("cypherchat.appearance")),
    );
  } catch {
    return { ...defaults };
  }
}
export function applyTheme(theme) {
  const root = document.documentElement;
  root.dataset.theme =
    theme.mode === "system"
      ? matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
      : theme.mode;
  root.dataset.motion = theme.motion ? "on" : "off";
  root.style.setProperty("--accent", theme.primary);
  root.style.setProperty("--secondary", theme.secondary);
  root.style.setProperty("--on-accent", foreground(theme.primary));
}
