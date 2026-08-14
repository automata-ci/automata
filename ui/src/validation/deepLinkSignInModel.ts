import { validateShell } from "./commonModels";
import { expectLiteral, expectObject, invalid } from "./primitives";

export function validateDeepLinkSignInPage(value: unknown, path: string): void {
  const page = expectObject(value, path, ["kind", "shell"]);
  expectLiteral(page.kind, `${path}.kind`, "deep-link-sign-in");
  validateShell(page.shell, `${path}.shell`);
  const shell = expectObject(page.shell, `${path}.shell`, [
    "productName",
    "homeHref",
    "signIn",
    "signOut",
    "documentTitle",
    "description",
    "viewer",
    "navigation",
  ]);
  if (shell.viewer !== null || shell.signIn === null || shell.signOut !== null) {
    invalid(`${path}.shell`, "an anonymous shell with one sign-in capability");
  }
}
