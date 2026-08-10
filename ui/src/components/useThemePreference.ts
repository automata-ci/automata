import { useCallback, useEffect, useRef, useState } from "react";

type Theme = "light" | "dark";

const THEME_STORAGE_KEY = "automata-theme";

export const THEME_BOOTSTRAP_SCRIPT = `try{const theme=localStorage.getItem(${JSON.stringify(
  THEME_STORAGE_KEY,
)});if(theme==="light"||theme==="dark"){document.documentElement.dataset.theme=theme}}catch{}`;

interface ThemePreference {
  readonly chooseNextTheme: () => void;
  readonly theme: Theme | null;
}

/** Synchronizes the explicit choice, system preference, DOM, and other tabs. */
export function useThemePreference(): ThemePreference {
  const [theme, setTheme] = useState<Theme | null>(null);
  const hasExplicitTheme = useRef(false);

  useEffect(() => {
    const media = darkModeMedia();
    const storedTheme = readStoredTheme();
    hasExplicitTheme.current = storedTheme !== null;
    applyTheme(storedTheme ?? systemTheme(media), setTheme);

    const followSystemTheme = () => {
      if (!hasExplicitTheme.current) {
        applyTheme(systemTheme(media), setTheme);
      }
    };
    const followStoredTheme = (event: StorageEvent) => {
      const storage = browserLocalStorage();
      if (storage === null || event.storageArea !== storage) {
        return;
      }
      if (event.key !== THEME_STORAGE_KEY && event.key !== null) {
        return;
      }
      const nextStoredTheme = parseTheme(event.newValue);
      hasExplicitTheme.current = nextStoredTheme !== null;
      applyTheme(nextStoredTheme ?? systemTheme(media), setTheme);
    };

    media?.addEventListener("change", followSystemTheme);
    window.addEventListener("storage", followStoredTheme);
    return () => {
      media?.removeEventListener("change", followSystemTheme);
      window.removeEventListener("storage", followStoredTheme);
    };
  }, []);

  const chooseNextTheme = useCallback(() => {
    const currentTheme = theme ?? systemTheme(darkModeMedia());
    const nextTheme: Theme = currentTheme === "dark" ? "light" : "dark";
    hasExplicitTheme.current = true;
    applyTheme(nextTheme, setTheme);
    try {
      browserLocalStorage()?.setItem(THEME_STORAGE_KEY, nextTheme);
    } catch {
      // The choice still applies to this document when storage is unavailable.
    }
  }, [theme]);

  return { chooseNextTheme, theme };
}

function applyTheme(theme: Theme, update: (theme: Theme) => void): void {
  document.documentElement.dataset.theme = theme;
  update(theme);
}

function darkModeMedia(): MediaQueryList | null {
  return typeof window.matchMedia === "function"
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : null;
}

function systemTheme(media: MediaQueryList | null): Theme {
  return media?.matches === true ? "dark" : "light";
}

function readStoredTheme(): Theme | null {
  try {
    return parseTheme(browserLocalStorage()?.getItem(THEME_STORAGE_KEY) ?? null);
  } catch {
    return null;
  }
}

function browserLocalStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function parseTheme(value: string | null): Theme | null {
  return value === "light" || value === "dark" ? value : null;
}
