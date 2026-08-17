import type { ReactNode } from "react";
import type { RunnerDirectoryItemModel, RunnerDirectoryPageModel } from "../models";
import { EmptyState } from "../components/EmptyState";
import { Shell } from "../components/Shell";
import { StatusBadge } from "../components/StatusBadge";

export interface RunnerDirectoryPageProps {
  readonly model: RunnerDirectoryPageModel;
  readonly shellUtility?: ReactNode;
}

export function RunnerDirectoryPage({ model, shellUtility }: RunnerDirectoryPageProps) {
  const visibilityLabel = model.visibility === "public" ? "Public directory" : "Private directory";

  return (
    <Shell shell={model.shell} repository={null} utility={shellUtility}>
      <main className="layout-width page runner-directory" id="main-content" tabIndex={-1}>
        <header className="page-heading runner-directory__heading">
          <div>
            <h1>{model.heading}</h1>
            <p>{model.summary}</p>
          </div>
          <span className={`runner-directory__visibility runner-directory__visibility--${model.visibility}`}>
            {visibilityLabel}
          </span>
        </header>

        <dl aria-label="Runner fleet summary" className="runner-directory__stats">
          <FleetStat label="Total runners" value={model.counts.total} />
          <FleetStat label="Online" value={model.counts.online} />
          <FleetStat label="Busy slots" value={`${model.counts.busySlots} / ${model.counts.totalSlots}`} />
        </dl>

        <section aria-labelledby="runner-list-heading" className="panel">
          <div className="panel__heading">
            <h2 id="runner-list-heading">Available runners</h2>
            <span>{model.runners.length} {model.runners.length === 1 ? "runner" : "runners"}</span>
          </div>
          {model.runners.length === 0 ? (
            <EmptyState description="No runners are registered for this tenant." heading="No runners available" headingLevel="h3" icon="actions" />
          ) : (
            <ul className="runner-directory__list">
              {model.runners.map((runner) => (
                <RunnerRow key={`${runner.group ?? "ungrouped"}/${runner.name}`} runner={runner} />
              ))}
            </ul>
          )}
        </section>
      </main>
    </Shell>
  );
}

function FleetStat({ label, value }: { readonly label: string; readonly value: number | string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function RunnerRow({ runner }: { readonly runner: RunnerDirectoryItemModel }) {
  return (
    <li className="runner-directory__item">
      <div className="runner-directory__identity">
        <div className="runner-directory__name-line">
          <strong>{runner.name}</strong>
          <StatusBadge status={runner.status} />
          {runner.desiredState === "active" ? null : (
            <span className={`runner-directory__desired runner-directory__desired--${runner.desiredState}`}>
              {runner.desiredStateLabel}
            </span>
          )}
        </div>
        <span className="runner-directory__group">{runner.group ?? "Ungrouped"}</span>
        {runner.labels.length === 0 ? null : (
          <ul aria-label={`${runner.name} labels`} className="runner-directory__labels">
            {runner.labels.map((label) => <li key={label}>{label}</li>)}
          </ul>
        )}
      </div>
      <dl className="runner-directory__facts">
        <div><dt>Capacity</dt><dd>{runner.busySlots} / {runner.totalSlots} busy</dd></div>
        <div><dt>Scheduling</dt><dd>{runner.desiredStateLabel}</dd></div>
        <div>
          <dt>Last contact</dt>
          <dd>{runner.lastSeenAt === null ? "Never" : <time dateTime={runner.lastSeenAt.iso}>{runner.lastSeenAt.label}</time>}</dd>
        </div>
      </dl>
    </li>
  );
}
