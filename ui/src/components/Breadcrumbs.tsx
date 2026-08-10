import { Icon } from "./Icon";

export interface BreadcrumbItem {
  readonly href: string | null;
  readonly label: string;
}

export interface BreadcrumbsProps {
  readonly items: readonly BreadcrumbItem[];
}

export function Breadcrumbs({ items }: BreadcrumbsProps) {
  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      <ol className="breadcrumbs__list">
        {items.map((item, index) => {
          const isCurrent = index === items.length - 1;
          return (
            <li className="breadcrumbs__item" key={`${index}:${item.href ?? ""}:${item.label}`}>
              {index === 0 ? null : (
                <Icon className="breadcrumbs__separator" name="chevron-right" size={14} />
              )}
              {item.href === null ? (
                <span aria-current={isCurrent ? "page" : undefined}>{item.label}</span>
              ) : (
                <a href={item.href} aria-current={isCurrent ? "page" : undefined}>
                  {item.label}
                </a>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
