import { afterEach, describe, expect, it } from "vitest";
import { installViewerMenuDismissal } from "../../src/enhancements/viewerMenu";

afterEach(() => {
  document.body.replaceChildren();
});

describe("viewer menu dismissal", () => {
  it("keeps inside interactions open and closes on an outside pointer", () => {
    document.body.innerHTML = `
      <details class="viewer-menu" open>
        <summary>Account</summary>
        <a href="/settings">Settings</a>
      </details>
      <main>Outside</main>
    `;
    const menu = requiredElement(
      document.querySelector<HTMLDetailsElement>(".viewer-menu"),
    );
    const settings = requiredElement(menu.querySelector("a"));
    const outside = requiredElement(document.querySelector("main"));
    const remove = installViewerMenuDismissal(document);

    settings.dispatchEvent(pointerDown());
    expect(menu.open).toBe(true);

    outside.dispatchEvent(pointerDown());
    expect(menu.open).toBe(false);

    remove();
    menu.open = true;
    outside.dispatchEvent(pointerDown());
    expect(menu.open).toBe(true);
  });
});

function pointerDown(): MouseEvent {
  return new MouseEvent("pointerdown", { bubbles: true, composed: true });
}

function requiredElement<T extends Element>(element: T | null): T {
  if (!element) {
    throw new Error("Expected the viewer-menu test fixture element");
  }
  return element;
}
