/**
 * A compact visual separator whose punctuation remains meaningful when the
 * decorative middle dot is omitted from the accessibility tree.
 */
export function MetadataSeparator() {
  return (
    <>
      {" "}
      <span aria-hidden="true">·</span>
      <span className="sr-only">,</span>{" "}
    </>
  );
}
