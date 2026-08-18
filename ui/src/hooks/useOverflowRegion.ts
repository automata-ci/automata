import { useEffect, useRef, useState } from "react";

/** Tracks whether a horizontally scrollable region needs keyboard focus. */
export function useOverflowRegion() {
  const regionRef = useRef<HTMLDivElement>(null);
  const [isOverflowing, setIsOverflowing] = useState(false);

  useEffect(() => {
    const region = regionRef.current;
    if (region === null) return;

    const updateOverflow = () => {
      setIsOverflowing(region.scrollWidth > region.clientWidth);
    };
    updateOverflow();
    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", updateOverflow);
      return () => window.removeEventListener("resize", updateOverflow);
    }

    const observer = new ResizeObserver(updateOverflow);
    observer.observe(region);
    if (region.firstElementChild !== null) {
      observer.observe(region.firstElementChild);
    }
    return () => observer.disconnect();
  }, []);

  return { isOverflowing, regionRef } as const;
}
