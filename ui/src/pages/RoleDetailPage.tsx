import type { ReactNode } from "react";
import type { RoleDetailPageModel } from "../models";
import { AuthorizationMutationFields } from "../components/AuthorizationMutationFields";
import { enforceRbacDisplayNameValidity } from "../components/rbacInputConstraints";
import {
  RbacManagement,
  RbacPermissionStatus,
  RbacTableRegion,
} from "../components/RbacManagement";

export interface RoleDetailPageProps {
  readonly model: RoleDetailPageModel;
  readonly shellUtility?: ReactNode;
}

export function RoleDetailPage({ model, shellUtility }: RoleDetailPageProps) {
  return (
    <RbacManagement
      heading={model.heading}
      managementNav={model.managementNav}
      notice={model.notice}
      shell={model.shell}
      shellUtility={shellUtility}
      summary={model.summary}
    >
      <section className="panel rbac-panel" aria-labelledby="role-details-heading">
        <div className="panel__heading">
          <h2 id="role-details-heading">Role details</h2>
        </div>
        <dl className="rbac-definition-list">
          <div>
            <dt>Display name</dt>
            <dd>{model.role.displayName}</dd>
          </div>
          <div>
            <dt>Policy name</dt>
            <dd><code>{model.role.name}</code></dd>
          </div>
          <div>
            <dt>Kind</dt>
            <dd>{model.role.kind === "built-in" ? "Built-in" : "Custom"}</dd>
          </div>
        </dl>
        {model.update === null && model.delete === null ? (
          <p className="rbac-read-only" role="note">
            {model.role.immutable
              ? "Built-in roles are defined by this release and are read-only."
              : "Role changes aren’t available with your current access."}
          </p>
        ) : (
          <div className="rbac-form-stack">
            {model.update === null ? (
              <p className="rbac-read-only" role="note">
                This role can no longer be changed, but it can still be deleted.
              </p>
            ) : (
              <form action={model.update.action} className="rbac-native-form" method="post">
                <AuthorizationMutationFields capability={model.update} />
                <input
                  name="expected_revision"
                  type="hidden"
                  value={model.update.expectedRevision}
                />
                <label>
                  Display name
                  <input
                    className="form-control"
                    defaultValue={model.role.displayName}
                    maxLength={255}
                    name="display_name"
                    onInput={(event) =>
                      enforceRbacDisplayNameValidity(event.currentTarget)
                    }
                    required
                  />
                </label>
                <button className="button" type="submit">Save role</button>
              </form>
            )}
            {model.delete === null ? null : (
              <details className="rbac-delete-disclosure">
                <summary>Delete role</summary>
                <div className="rbac-delete-disclosure__confirmation">
                  <p>
                    Delete <strong>{model.role.displayName}</strong>? This can’t be
                    undone.
                  </p>
                  <form
                    action={model.delete.action}
                    className="rbac-native-form"
                    method="post"
                  >
                    <AuthorizationMutationFields capability={model.delete} />
                    <input
                      name="expected_revision"
                      type="hidden"
                      value={model.delete.expectedRevision}
                    />
                    <button className="button button--danger" type="submit">
                      Confirm delete
                    </button>
                  </form>
                </div>
              </details>
            )}
          </div>
        )}
      </section>

      <section
        aria-labelledby={
          model.permissions.length === 0 ? "role-permissions-heading" : undefined
        }
        className="panel rbac-panel"
      >
        <div className="panel__heading">
          <h2 id="role-permissions-heading">Permissions</h2>
          <span>{model.role.permissionCount} granted</span>
        </div>
        {model.permissions.length === 0 ? (
          <p className="rbac-empty">No permissions are available to display.</p>
        ) : (
          <RbacTableRegion labelledBy="role-permissions-heading">
            <table className="rbac-table">
              <caption className="sr-only">
                Permission catalog and explicit grants for this role
              </caption>
              <thead>
                <tr>
                  <th scope="col">Permission</th>
                  <th scope="col">Grant</th>
                </tr>
              </thead>
              <tbody>
                {model.permissions.map((permission) => (
                  <tr key={permission.name}>
                    <th data-label="Permission" scope="row">
                      <span className="rbac-cell-stack">
                        <code>{permission.name}</code>
                        <small>{permission.description}</small>
                      </span>
                    </th>
                    <td data-label="Grant">
                      <span className="rbac-permission-action">
                        <RbacPermissionStatus granted={permission.granted} />
                        {permission.update === null ? null : (
                          <form action={permission.update.action} method="post">
                            <AuthorizationMutationFields
                              capability={permission.update}
                            />
                            <input
                              name="expected_revision"
                              type="hidden"
                              value={permission.update.expectedRevision}
                            />
                            <input
                              name="operation"
                              type="hidden"
                              value={permission.update.operation}
                            />
                            <button
                              aria-label={
                                permission.update.operation === "add"
                                  ? `Grant ${permission.name} permission to role ${model.role.displayName}`
                                  : `Remove ${permission.name} permission from role ${model.role.displayName}`
                              }
                              className="button button--compact"
                              type="submit"
                            >
                              {permission.update.operation === "add" ? "Grant" : "Remove"}
                            </button>
                          </form>
                        )}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </RbacTableRegion>
        )}
      </section>
    </RbacManagement>
  );
}
