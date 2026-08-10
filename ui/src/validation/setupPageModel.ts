import { validateShell } from "./commonModels";
import {
  expectLiteral,
  expectObject,
  field,
  invalid,
} from "./primitives";

const SETUP_DESCRIPTION =
  "Complete the one-time administrator setup for this Automata installation.";

export function validateSetupPage(value: unknown, path: string): void {
  const page = expectObject(value, path, ["kind", "shell", "form"]);
  expectLiteral(page.kind, `${path}.kind`, "setup");

  const shellPath = `${path}.shell`;
  const shell = expectObject(field(page, "shell", path), shellPath, [
    "productName",
    "homeHref",
    "signIn",
    "signOut",
    "documentTitle",
    "description",
    "viewer",
    "navigation",
  ]);
  const shellContext = validateShell(shell, shellPath);
  expectLiteral(shell.productName, `${shellPath}.productName`, "Automata");
  expectLiteral(shell.homeHref, `${shellPath}.homeHref`, "/setup");
  expectLiteral(shell.documentTitle, `${shellPath}.documentTitle`, "Set up Automata");
  expectLiteral(shell.description, `${shellPath}.description`, SETUP_DESCRIPTION);
  if (shell.signIn !== null || shell.signOut !== null || shell.viewer !== null) {
    invalid(shellPath, "an anonymous setup-only shell without account actions");
  }
  const [navigation] = shellContext.navigation;
  if (
    shellContext.navigation.length !== 1 ||
    navigation?.label !== "Setup" ||
    navigation.href !== "/setup" ||
    !navigation.current
  ) {
    invalid(`${shellPath}.navigation`, "the sole current Setup destination");
  }

  const formPath = `${path}.form`;
  const form = expectObject(field(page, "form", path), formPath, [
    "action",
    "returnPath",
  ]);
  expectLiteral(form.action, `${formPath}.action`, "/setup/auth/github");
  expectLiteral(form.returnPath, `${formPath}.returnPath`, "/");
}
