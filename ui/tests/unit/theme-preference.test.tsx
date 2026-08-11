import { act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  THEME_BOOTSTRAP_SCRIPT,
  useThemePreference,
} from "../../src/components/useThemePreference";

const THEME_STORAGE_KEY = "automata-theme";

let root: Root | null = null;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  document.body.replaceChildren();
  document.documentElement.removeAttribute("data-theme");
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("theme preference lifecycle", () => {
  it("initializes from a valid stored preference before the system setting", async () => {
    const media = controlledMediaQuery(true);
    const storage = memoryStorage([[THEME_STORAGE_KEY, "light"]]);
    vi.stubGlobal("matchMedia", vi.fn(() => media.query));
    vi.stubGlobal("localStorage", storage);

    const button = await renderThemeHarness();

    expect(document.documentElement.dataset.theme).toBe("light");
    expect(button.textContent).toBe("light");
    expect(storage.getItem).toHaveBeenCalledWith(THEME_STORAGE_KEY);
    expect(window.matchMedia).toHaveBeenCalledWith(
      "(prefers-color-scheme: dark)",
    );
  });

  it("follows system changes only while there is no explicit preference", async () => {
    const media = controlledMediaQuery(false);
    const storage = memoryStorage();
    vi.stubGlobal("matchMedia", vi.fn(() => media.query));
    vi.stubGlobal("localStorage", storage);

    const button = await renderThemeHarness();
    expect(document.documentElement.dataset.theme).toBe("light");

    await act(async () => media.setMatches(true));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(button.textContent).toBe("dark");

    await act(async () => button.click());
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(storage.setItem).toHaveBeenCalledWith(THEME_STORAGE_KEY, "light");

    await act(async () => media.setMatches(false));
    await act(async () => media.setMatches(true));
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("synchronizes relevant storage changes and returns to the system theme when cleared", async () => {
    const media = controlledMediaQuery(true);
    const storage = memoryStorage();
    const otherStorage = memoryStorage();
    vi.stubGlobal("matchMedia", vi.fn(() => media.query));
    vi.stubGlobal("localStorage", storage);

    const button = await renderThemeHarness();
    expect(button.textContent).toBe("dark");

    await act(async () => {
      window.dispatchEvent(
        storageEvent(otherStorage, THEME_STORAGE_KEY, "light"),
      );
      window.dispatchEvent(storageEvent(storage, "unrelated", "light"));
    });
    expect(document.documentElement.dataset.theme).toBe("dark");

    await act(async () => {
      window.dispatchEvent(
        storageEvent(storage, THEME_STORAGE_KEY, "light"),
      );
    });
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(button.textContent).toBe("light");

    await act(async () => {
      window.dispatchEvent(storageEvent(storage, null, null));
    });
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(button.textContent).toBe("dark");
  });

  it("removes the exact media and storage listeners when unmounted", async () => {
    const media = controlledMediaQuery(false);
    const storage = memoryStorage();
    const addWindowListener = vi.spyOn(window, "addEventListener");
    const removeWindowListener = vi.spyOn(window, "removeEventListener");
    vi.stubGlobal("matchMedia", vi.fn(() => media.query));
    vi.stubGlobal("localStorage", storage);

    await renderThemeHarness();
    const mediaListener = media.addEventListener.mock.calls.find(
      ([type]) => type === "change",
    )?.[1];
    const storageListener = addWindowListener.mock.calls.find(
      ([type]) => type === "storage",
    )?.[1];
    expect(mediaListener).toBeDefined();
    expect(storageListener).toBeDefined();

    await act(async () => root?.unmount());
    root = null;

    expect(media.removeEventListener).toHaveBeenCalledWith(
      "change",
      mediaListener,
    );
    expect(removeWindowListener).toHaveBeenCalledWith(
      "storage",
      storageListener,
    );
  });

  it("keeps working when browser storage is unavailable", async () => {
    const media = controlledMediaQuery(true);
    const localStorageDescriptor = Object.getOwnPropertyDescriptor(
      window,
      "localStorage",
    );
    vi.stubGlobal("matchMedia", vi.fn(() => media.query));
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      get: () => {
        throw new DOMException("Storage is unavailable", "SecurityError");
      },
    });

    try {
      const button = await renderThemeHarness();
      expect(document.documentElement.dataset.theme).toBe("dark");

      await act(async () => button.click());
      expect(document.documentElement.dataset.theme).toBe("light");
      expect(button.textContent).toBe("light");
    } finally {
      if (localStorageDescriptor !== undefined) {
        Object.defineProperty(window, "localStorage", localStorageDescriptor);
      }
    }
  });

  it("falls back when storage operations themselves fail", async () => {
    const media = controlledMediaQuery(true);
    const storage = memoryStorage();
    storage.getItem.mockImplementation(() => {
      throw new DOMException("Read failed", "SecurityError");
    });
    storage.setItem.mockImplementation(() => {
      throw new DOMException("Write failed", "QuotaExceededError");
    });
    vi.stubGlobal("matchMedia", vi.fn(() => media.query));
    vi.stubGlobal("localStorage", storage);

    const button = await renderThemeHarness();
    expect(document.documentElement.dataset.theme).toBe("dark");

    await act(async () => button.click());
    expect(storage.setItem).toHaveBeenCalledWith(THEME_STORAGE_KEY, "light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(button.textContent).toBe("light");
  });
});

describe("pre-hydration theme bootstrap", () => {
  it("applies only valid stored themes and suppresses storage failures", () => {
    const runBootstrap = (storage: Pick<Storage, "getItem">) =>
      Function(
        "localStorage",
        "document",
        THEME_BOOTSTRAP_SCRIPT,
      )(storage, document);

    runBootstrap({ getItem: () => "dark" });
    expect(document.documentElement.dataset.theme).toBe("dark");

    document.documentElement.removeAttribute("data-theme");
    runBootstrap({ getItem: () => "sepia" });
    expect(document.documentElement.dataset.theme).toBeUndefined();

    expect(() =>
      runBootstrap({
        getItem: () => {
          throw new DOMException("Storage is unavailable", "SecurityError");
        },
      }),
    ).not.toThrow();
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });
});

function ThemeHarness() {
  const { chooseNextTheme, theme } = useThemePreference();
  return (
    <button onClick={chooseNextTheme} type="button">
      {theme ?? "pending"}
    </button>
  );
}

async function renderThemeHarness(): Promise<HTMLButtonElement> {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root?.render(<ThemeHarness />));
  const button = container.querySelector("button");
  if (button === null) {
    throw new Error("The theme harness did not render");
  }
  return button;
}

function controlledMediaQuery(initialMatches: boolean) {
  let matches = initialMatches;
  const listeners = new Set<(event: MediaQueryListEvent) => void>();
  const addEventListener = vi.fn(
    (type: string, listener: EventListenerOrEventListenerObject) => {
      if (type === "change" && typeof listener === "function") {
        listeners.add(listener as (event: MediaQueryListEvent) => void);
      }
    },
  );
  const removeEventListener = vi.fn(
    (type: string, listener: EventListenerOrEventListenerObject) => {
      if (type === "change" && typeof listener === "function") {
        listeners.delete(listener as (event: MediaQueryListEvent) => void);
      }
    },
  );
  const query = {
    get matches() {
      return matches;
    },
    media: "(prefers-color-scheme: dark)",
    onchange: null,
    addEventListener,
    removeEventListener,
  } as unknown as MediaQueryList;

  return {
    addEventListener,
    query,
    removeEventListener,
    setMatches(nextMatches: boolean) {
      matches = nextMatches;
      const event = { matches, media: query.media } as MediaQueryListEvent;
      for (const listener of listeners) {
        listener(event);
      }
    },
  };
}

function memoryStorage(
  entries: readonly (readonly [key: string, value: string])[] = [],
): Storage & {
  readonly getItem: ReturnType<typeof vi.fn>;
  readonly setItem: ReturnType<typeof vi.fn>;
} {
  const values = new Map(entries);
  const storage = {
    get length() {
      return values.size;
    },
    clear: vi.fn(() => values.clear()),
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    key: vi.fn((index: number) => [...values.keys()][index] ?? null),
    removeItem: vi.fn((key: string) => values.delete(key)),
    setItem: vi.fn((key: string, value: string) => values.set(key, value)),
  };
  return storage as Storage & {
    readonly getItem: ReturnType<typeof vi.fn>;
    readonly setItem: ReturnType<typeof vi.fn>;
  };
}

function storageEvent(
  storageArea: Storage,
  key: string | null,
  newValue: string | null,
): StorageEvent {
  const event = new Event("storage") as StorageEvent;
  Object.defineProperties(event, {
    key: { value: key },
    newValue: { value: newValue },
    storageArea: { value: storageArea },
  });
  return event;
}
