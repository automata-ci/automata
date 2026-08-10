export type IconName =
  | "actions"
  | "artifact"
  | "branch"
  | "chevron-down"
  | "chevron-right"
  | "commit"
  | "overview"
  | "pull-request"
  | "repository"
  | "search"
  | "settings"
  | "sign-out"
  | "moon"
  | "sun"
  | "tag"
  | "workflow";

export interface IconProps {
  readonly name: IconName;
  readonly size?: 14 | 15 | 16 | 18 | 20 | 24;
  readonly className?: string;
}

const phosphorIconNames: Readonly<Record<IconName, string>> = {
  actions: "play-circle",
  artifact: "package",
  branch: "git-branch",
  "chevron-down": "caret-down",
  "chevron-right": "caret-right",
  commit: "git-commit",
  overview: "book-open",
  "pull-request": "git-pull-request",
  repository: "book-bookmark",
  search: "magnifying-glass",
  settings: "gear-six",
  "sign-out": "sign-out",
  moon: "moon",
  sun: "sun",
  tag: "tag",
  workflow: "path",
};

/** Decorative icons from the locally bundled Phosphor regular icon font. */
export function Icon({ name, size = 16, className }: IconProps) {
  const classes = `ph ph-${phosphorIconNames[name]} icon icon--${size}${
    className === undefined ? "" : ` ${className}`
  }`;

  return <i aria-hidden="true" className={classes} />;
}
