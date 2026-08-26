/**
 * Closes an open account disclosure when a pointer interaction starts outside
 * it. The caller owns the document listener's lifetime.
 */
export function installViewerMenuDismissal(
  ownerDocument: Document,
): () => void {
  const dismissOutsideMenu = (event: PointerEvent) => {
    const eventPath = event.composedPath();
    for (const menu of ownerDocument.querySelectorAll<HTMLDetailsElement>(
      "details.viewer-menu[open]",
    )) {
      if (!eventPath.includes(menu)) {
        menu.open = false;
      }
    }
  };

  ownerDocument.addEventListener("pointerdown", dismissOutsideMenu, true);
  return () => {
    ownerDocument.removeEventListener("pointerdown", dismissOutsideMenu, true);
  };
}
