import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { App, PreviewApp } from "./App";
import { EmptyState } from "./components/EmptyState";
import { Shell } from "./components/Shell";
import { ThemeToggle } from "./components/ThemeToggle";
import type { PageModel } from "./models";
import type { LiveLogRecord } from "./liveLogs/sse";
import "./styles.css";
import "./styles/pages/preview.css";
import { installPreviewFormRouting } from "./preview/formRouting";
import {
  isPreviewJobLogStateSupported,
  isPreviewRepositoryDirectoryStateSupported,
  isPreviewRepositorySettingsStateSupported,
  isPreviewRepositorySecretsStateSupported,
  isPreviewRunDetailStateSupported,
  isPreviewRunListStateSupported,
  previewJobLog,
  previewJobLogRecords,
  previewRepositoryDirectory,
  previewRepositorySettings,
  previewRepositorySecrets,
  previewRunDetail,
  previewRunList,
} from "./preview/models";
import {
  PREVIEW_RBAC_VIEWS,
  previewRbacPage,
} from "./preview/rbacModels";
import type { PreviewRbacView } from "./preview/rbacModels";

const previewRoot = document.getElementById("root");
if (previewRoot === null) {
  throw new Error("The UI preview root is missing");
}
const previewRootElement = previewRoot;
const hotData = import.meta.hot?.data as PreviewHotData | undefined;
const reactRoot = hotData?.reactRoot ?? createRoot(previewRootElement);
if (hotData !== undefined) {
  hotData.reactRoot = reactRoot;
}
const removePreviewFormRouting = installPreviewFormRouting(previewRootElement);
import.meta.hot?.dispose((data: PreviewHotData) => {
  removePreviewFormRouting();
  data.reactRoot = reactRoot;
});

const searchParameters = new URLSearchParams(window.location.search);
const view = searchParameters.get("view");
const requestedRunId = searchParameters.get("run");
const requestedJobId = searchParameters.get("job");

if (view === null || view === "repositories" || view === "repositories-empty") {
  if (isPreviewRepositoryDirectoryStateSupported(searchParameters)) {
    renderPreviewPage(previewRepositoryDirectory(view === "repositories-empty"));
  } else {
    renderNotFound(
      "Page not found",
      "Those repository directory parameters are not part of this demo.",
    );
  }
} else if (view === "run") {
  const runDetail = isPreviewRunDetailStateSupported(searchParameters)
    ? previewRunDetail(requestedRunId)
    : null;
  if (runDetail === null) {
    renderNotFound("Run not found", "That workflow run is not part of this demo.");
  } else {
    renderPreviewPage(runDetail);
  }
} else if (view === "job") {
  const jobLog = isPreviewJobLogStateSupported(searchParameters)
    ? previewJobLog(requestedRunId, requestedJobId)
    : null;
  if (jobLog === null) {
    renderNotFound("Job not found", "That workflow job is not part of this demo.");
  } else {
    renderPreviewJobLog(
      jobLog,
      previewJobLogRecords(requestedRunId, requestedJobId),
    );
  }
} else if (view === "settings") {
  if (isPreviewRepositorySettingsStateSupported(searchParameters)) {
    renderPreviewPage(previewRepositorySettings());
  } else {
    renderNotFound(
      "Page not found",
      "Those repository settings parameters are not part of this demo.",
    );
  }
} else if (view === "secrets") {
  if (isPreviewRepositorySecretsStateSupported(searchParameters)) {
    renderPreviewPage(previewRepositorySecrets());
  } else {
    renderNotFound(
      "Page not found",
      "Those repository secrets parameters are not part of this demo.",
    );
  }
} else if (view !== null && PREVIEW_RBAC_VIEWS.has(view)) {
  const managementPage = previewRbacPage(
    view as PreviewRbacView,
    searchParameters,
  );
  if (managementPage === null) {
    renderNotFound(
      "Page not found",
      "Those access management parameters are not part of this demo.",
    );
  } else {
    renderPreviewPage(managementPage);
  }
} else if (view === "runs") {
  if (isPreviewRunListStateSupported(searchParameters)) {
    renderPreviewPage(previewRunList(searchParameters));
  } else {
    renderNotFound(
      "Page not found",
      "Those workflow run filters are not part of this demo.",
    );
  }
} else {
  renderNotFound("Page not found", "That page is not part of this demo.");
}

function renderPreviewPage(page: PageModel): void {
  document.title = page.shell.documentTitle;
  reactRoot.render(
    <App page={page} shellUtility={<PreviewTools />} />,
  );
  reconcilePreviewHashTarget();
}

function renderPreviewJobLog(
  page: PageModel,
  records: readonly LiveLogRecord[],
): void {
  document.title = page.shell.documentTitle;
  reactRoot.render(
    <PreviewApp
      initialJobLogRecords={records}
      page={page}
      shellUtility={<PreviewTools />}
    />,
  );
  reconcilePreviewHashTarget();
}

function reconcilePreviewHashTarget(remainingFrames = 2): void {
  if (window.location.hash.length <= 1) {
    return;
  }
  let targetId: string;
  try {
    targetId = decodeURIComponent(window.location.hash.slice(1));
  } catch {
    return;
  }
  const target = document.getElementById(targetId);
  if (target !== null) {
    target.classList.add("preview-hash-target");
    target.focus({ preventScroll: true });
    target.scrollIntoView({ block: "center" });
    return;
  }
  if (remainingFrames > 0) {
    requestAnimationFrame(() =>
      reconcilePreviewHashTarget(remainingFrames - 1),
    );
  }
}

// The export gives React Fast Refresh a stable component boundary.
export function PreviewTools() {
  return (
    <>
      <span
        aria-label="Sample data — preview only; no backend workflows were executed."
        className="demo-badge"
        role="note"
      >
        <span className="demo-badge__wide" aria-hidden="true">Sample data</span>
        {" "}
        <span className="demo-badge__compact" aria-hidden="true">Demo</span>
      </span>
      <ThemeToggle />
    </>
  );
}

function renderNotFound(heading: string, message: string): void {
  const home = previewRepositoryDirectory();
  document.title = `${heading} · Automata`;
  reactRoot.render(
    <Shell shell={home.shell} repository={null} utility={<PreviewTools />}>
      <main className="layout-wide page" id="main-content" tabIndex={-1}>
        <div className="preview-not-found">
          <EmptyState
            action={
              <a className="button" href="?view=repositories">
                Back to repositories
              </a>
            }
            description={message}
            heading={heading}
            headingLevel="h1"
            icon="actions"
          />
        </div>
      </main>
    </Shell>,
  );
}

// Vite preserves this bag across module replacements, so development updates
// reuse the React root. The submit adapter is removed during disposal and then
// reinstalled from the new module, keeping its behavior current after HMR.
interface PreviewHotData {
  reactRoot?: Root;
}
