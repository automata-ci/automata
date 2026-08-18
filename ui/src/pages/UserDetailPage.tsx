import type { ReactNode } from "react";
import type { UserDetailPageModel } from "../models";
import { AuthorizationMutationFields } from "../components/AuthorizationMutationFields";
import { enforceRbacReasonValidity } from "../components/rbacInputConstraints";
import {
  RbacManagement,
  RbacScope,
  RbacStatus,
  RbacTableRegion,
  rbacProviderLabel,
} from "../components/RbacManagement";

export interface UserDetailPageProps {
  readonly model: UserDetailPageModel;
  readonly shellUtility?: ReactNode;
}

export function UserDetailPage({ model, shellUtility }: UserDetailPageProps) {
  return (
    <RbacManagement
      heading={model.heading}
      managementNav={model.managementNav}
      notice={model.notice}
      shell={model.shell}
      shellUtility={shellUtility}
      summary={model.summary}
    >
      <section className="panel rbac-panel" aria-labelledby="user-identity-heading">
        <div className="panel__heading">
          <h2 id="user-identity-heading">Member identity</h2>
          <RbacStatus status={model.user.status} />
        </div>
        <dl className="rbac-definition-list">
          <div>
            <dt>Display name</dt>
            <dd>{model.user.displayName ?? "Not provided"}</dd>
          </div>
          <div>
            <dt>Identity reference</dt>
            <dd>{model.user.providerLogin}</dd>
          </div>
          <div>
            <dt>Identity provider</dt>
            <dd>{rbacProviderLabel(model.user.providerId)}</dd>
          </div>
        </dl>
        {model.statusUpdate === null ? (
          <p className="rbac-read-only" role="note">
            Status changes aren’t available with your current access.
          </p>
        ) : (
          <form
            action={model.statusUpdate.action}
            className="rbac-native-form"
            method="post"
          >
            <AuthorizationMutationFields capability={model.statusUpdate} />
            <input
              name="expected_revision"
              type="hidden"
              value={model.statusUpdate.expectedRevision}
            />
            <input
              name="operation"
              type="hidden"
              value={model.statusUpdate.operation}
            />
            {model.statusUpdate.operation === "disable" ? (
              <label>
                Reason for disabling
                <input
                  className="form-control"
                  maxLength={1024}
                  name="reason"
                  onInput={(event) =>
                    enforceRbacReasonValidity(event.currentTarget)
                  }
                  required
                />
              </label>
            ) : null}
            <button
              className={
                model.statusUpdate.operation === "disable"
                  ? "button button--danger"
                  : "button"
              }
              type="submit"
            >
              {model.statusUpdate.operation === "disable" ? "Disable member" : "Enable member"}
            </button>
          </form>
        )}
      </section>

      <section
        aria-labelledby={
          model.roleAssignments.length === 0 ? "user-roles-heading" : undefined
        }
        className="panel rbac-panel"
      >
        <div className="panel__heading">
          <h2 id="user-roles-heading">Role assignments</h2>
          <span>{model.roleAssignments.length} visible</span>
        </div>
        {model.roleAssignments.length === 0 ? (
          <p className="rbac-empty">No role assignments are visible for this user.</p>
        ) : (
          <RbacTableRegion labelledBy="user-roles-heading">
            <table className="rbac-table">
              <caption className="sr-only">
                Roles assigned to this user and their exact scopes
              </caption>
              <thead>
                <tr>
                  <th scope="col">Role</th>
                  <th scope="col">Scope</th>
                  <th scope="col">Source</th>
                  <th scope="col">Status</th>
                  <th scope="col">Valid until</th>
                </tr>
              </thead>
              <tbody>
                {model.roleAssignments.map((assignment) => (
                  <tr key={assignment.bindingId}>
                    <th data-label="Role" scope="row">
                      <a className="rbac-primary-link" href={assignment.roleHref}>
                        {assignment.roleDisplayName}
                      </a>
                      <small>{assignment.roleName}</small>
                    </th>
                    <td data-label="Scope"><RbacScope scope={assignment.scope} /></td>
                    <td data-label="Source">
                      <a href={assignment.bindingHref}>
                        {assignment.source === "direct" ? "Direct" : "Provider observed"}
                      </a>
                    </td>
                    <td data-label="Status"><RbacStatus status={assignment.status} /></td>
                    <td data-label="Valid until">
                      {assignment.validUntil === null
                        ? "No expiry"
                        : (
                            <time dateTime={assignment.validUntil.iso}>
                              {assignment.validUntil.label}
                            </time>
                          )}
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
