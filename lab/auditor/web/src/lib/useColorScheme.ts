import { useEffect, useState } from "react";

/**
 * Independent of useTheme.ts's dark/light toggle - this is a second,
 * additive dimension. "default" is today's single amber-brand look
 * (unchanged in both dark and light); "kaustify" overrides --color-brand
 * and the 4 --color-phase-* custom properties (index.css) to KAUST's own
 * brand colors, layered on top of whichever dark/light mode is active.
 */
export type ColorScheme = "default" | "kaustify";

const STORAGE_KEY = "raqib-color-scheme";

function readStoredColorScheme(): ColorScheme {
  return localStorage.getItem(STORAGE_KEY) === "kaustify" ? "kaustify" : "default";
}

export function useColorScheme(): [ColorScheme, () => void] {
  const [colorScheme, setColorScheme] = useState<ColorScheme>(readStoredColorScheme);

  useEffect(() => {
    if (colorScheme === "kaustify") {
      document.documentElement.setAttribute("data-color-scheme", "kaustify");
    } else {
      document.documentElement.removeAttribute("data-color-scheme");
    }
    localStorage.setItem(STORAGE_KEY, colorScheme);
  }, [colorScheme]);

  function toggleColorScheme() {
    setColorScheme((prev) => (prev === "default" ? "kaustify" : "default"));
  }

  return [colorScheme, toggleColorScheme];
}
