import type { RepositorySettingsNavigationModel } from "../models";

export function RepositorySettingsNavigation({
  navigation,
}: {
  readonly navigation: RepositorySettingsNavigationModel;
}) {
  const links = [
    { area: "access", href: navigation.accessHref, label: "Access" },
    { area: "secrets", href: navigation.secretsHref, label: "Secrets" },
  ] as const;

  return (
    <nav
      aria-label="Repository settings"
      className="repository-settings-navigation"
    >
      {links.map((link) =>
        link.href === null ? null : (
          <a
            aria-current={navigation.current === link.area ? "page" : undefined}
            href={link.href}
            key={link.area}
          >
            {link.label}
          </a>
        ),
      )}
    </nav>
  );
}
