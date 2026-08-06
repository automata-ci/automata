use automata_ui_renderer::ClientAssetManifest;
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RenderRequest {
    schema_version: u8,
    host: RenderHost,
    page: RunListPage,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RenderHost {
    locale: &'static str,
    assets: RenderAssets,
    csp_nonce: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RenderAssets {
    client_entry: &'static str,
    stylesheets: &'static [&'static str],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunListPage {
    kind: &'static str,
    shell: Shell,
    repository: Repository,
    heading: &'static str,
    summary: &'static str,
    filters: RunFilters,
    runs: [(); 0],
    pagination: Pagination,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Shell {
    product_name: &'static str,
    home_href: &'static str,
    sign_in_href: &'static str,
    document_title: &'static str,
    description: &'static str,
    viewer: Option<()>,
    navigation: Vec<NavigationItem>,
}

#[derive(Debug, Serialize)]
struct NavigationItem {
    label: &'static str,
    href: &'static str,
    current: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Repository {
    owner: &'static str,
    name: &'static str,
    href: &'static str,
    runs_href: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunFilters {
    action: &'static str,
    status: String,
    branch: String,
    status_options: Vec<FilterOption>,
    clear_href: &'static str,
}

#[derive(Debug, Serialize)]
struct FilterOption {
    value: &'static str,
    label: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Pagination {
    previous_href: Option<String>,
    next_href: Option<String>,
    label: &'static str,
}

pub(super) fn empty_run_list(
    assets: ClientAssetManifest,
    csp_nonce: String,
    selected_status: String,
    branch: String,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(&RenderRequest {
        schema_version: 1,
        host: RenderHost {
            locale: "en",
            assets: RenderAssets {
                client_entry: assets.script_path,
                stylesheets: assets.stylesheet_paths,
            },
            csp_nonce,
        },
        page: RunListPage {
            kind: "run-list",
            shell: Shell {
                product_name: "Automata",
                home_href: "/",
                sign_in_href: "/login",
                document_title: "Workflow runs · Automata",
                description: "GitHub Actions-compatible workflow runs",
                viewer: None,
                navigation: vec![
                    NavigationItem {
                        label: "Repositories",
                        href: "/repositories",
                        current: false,
                    },
                    NavigationItem {
                        label: "Runs",
                        href: "/runs",
                        current: true,
                    },
                    NavigationItem {
                        label: "Runners",
                        href: "/runners",
                        current: false,
                    },
                ],
            },
            repository: Repository {
                owner: "AlexanderDzhoganov",
                name: "automata",
                href: "/AlexanderDzhoganov/automata",
                runs_href: "/runs",
            },
            heading: "Workflow runs",
            summary: "No workflow runs have been recorded by this control plane yet.",
            filters: RunFilters {
                action: "/runs",
                status: selected_status,
                branch,
                status_options: vec![
                    FilterOption {
                        value: "all",
                        label: "All statuses",
                    },
                    FilterOption {
                        value: "queued",
                        label: "Queued",
                    },
                    FilterOption {
                        value: "in_progress",
                        label: "In progress",
                    },
                    FilterOption {
                        value: "completed",
                        label: "Completed",
                    },
                ],
                clear_href: "/runs",
            },
            runs: [],
            pagination: Pagination {
                previous_href: None,
                next_href: None,
                label: "0 runs",
            },
        },
    })
}
