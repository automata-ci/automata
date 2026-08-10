import type { ReactNode } from "react";
import type { RoleListPageModel } from "../models";
import { Pagination } from "../components/Pagination";
import { enforceRbacDisplayNameValidity } from "../components/rbacInputConstraints";
import {
  RbacManagement,
  RbacMutationFields,
  RbacTableRegion,
} from "../components/RbacManagement";

export interface RoleListPageProps {
  readonly model: RoleListPageModel;
  readonly shellUtility?: ReactNode;
}

export function RoleListPage({ model, shellUtility }: RoleListPageProps) {
  return (
    <RbacManagement
      heading={model.heading}
      managementNav={model.managementNav}
      notice={model.notice}
      shell={model.shell}
      shellUtility={shellUtility}
      summary={model.summary}
    >
      {model.create === null ? null : (
        <section className="panel rbac-panel" aria-labelledby="create-role-heading">
          <div className="panel__heading">
            <h2 id="create-role-heading">Create custom role</h2>
          </div>
          <form action={model.create.action} className="rbac-native-form" method="post">
            <RbacMutationFields
              csrfToken={model.create.csrfToken}
              expectedAuthorizationRevision={model.create.expectedAuthorizationRevision}
            />
            <label>
              Policy name
              <input
                autoComplete="off"
                maxLength={128}
                name="name"
                pattern="[A-Za-z0-9_.:-]+"
                required
              />
            </label>
            <label>
              Display name
              <input
                autoComplete="off"
                maxLength={255}
                name="display_name"
                onInput={(event) =>
                  enforceRbacDisplayNameValidity(event.currentTarget)
                }
                required
              />
            </label>
            <button className="button" type="submit">Create role</button>
          </form>
        </section>
      )}
      <section
        aria-labelledby={model.roles.length === 0 ? "roles-heading" : undefined}
        className="panel rbac-panel"
      >
        <div className="panel__heading">
          <h2 id="roles-heading">Roles</h2>
          <span>{model.pagination.label}</span>
        </div>
        {model.roles.length === 0 ? (
          <p className="rbac-empty">No roles are available with your current access.</p>
        ) : (
          <RbacTableRegion labelledBy="roles-heading">
            <table className="rbac-table">
              <caption className="sr-only">
                Built-in and custom roles in this tenant
              </caption>
              <thead>
                <tr>
                  <th scope="col">Role</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Permissions</th>
                </tr>
              </thead>
              <tbody>
                {model.roles.map((role) => (
                  <tr key={role.id}>
                    <th data-label="Role" scope="row">
                      <a className="rbac-primary-link" href={role.href}>
                        {role.displayName}
                      </a>
                      <small>{role.name}</small>
                    </th>
                    <td data-label="Kind">
                      <span className="rbac-cell-stack">
                        <span>{role.kind === "built-in" ? "Built-in" : "Custom"}</span>
                        <small>{role.immutable ? "Release-defined" : "Tenant-defined"}</small>
                      </span>
                    </td>
                    <td data-label="Permissions">{role.permissionCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </RbacTableRegion>
        )}
      </section>
      <Pagination label="Roles pagination" pagination={model.pagination} />
    </RbacManagement>
  );
}
