import type { ReactNode } from "react";
import type { UserListPageModel } from "../models";
import { Pagination } from "../components/Pagination";
import {
  RbacManagement,
  RbacStatus,
  RbacTableRegion,
  rbacProviderLabel,
} from "../components/RbacManagement";

export interface UserListPageProps {
  readonly model: UserListPageModel;
  readonly shellUtility?: ReactNode;
}

export function UserListPage({ model, shellUtility }: UserListPageProps) {
  return (
    <RbacManagement
      heading={model.heading}
      managementNav={model.managementNav}
      notice={model.notice}
      shell={model.shell}
      shellUtility={shellUtility}
      summary={model.summary}
    >
      <section
        aria-labelledby={model.users.length === 0 ? "users-heading" : undefined}
        className="panel rbac-panel"
      >
        <div className="panel__heading">
          <h2 id="users-heading">Tenant members</h2>
          <span>{model.pagination.label}</span>
        </div>
        {model.users.length === 0 ? (
          <p className="rbac-empty">No members are available with your current access.</p>
        ) : (
          <RbacTableRegion labelledBy="users-heading">
            <table className="rbac-table">
              <caption className="sr-only">
                Human and delegated tenant identities and their current status
              </caption>
              <thead>
                <tr>
                  <th scope="col">Member</th>
                  <th scope="col">Identity</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {model.users.map((user) => (
                  <tr key={user.id}>
                    <th data-label="Member" scope="row">
                      <a className="rbac-primary-link" href={user.href}>
                        {user.displayName ?? user.providerLogin}
                      </a>
                    </th>
                    <td data-label="Identity">
                      <span className="rbac-cell-stack">
                        <span>{user.providerLogin}</span>
                        <small>{rbacProviderLabel(user.providerId)}</small>
                      </span>
                    </td>
                    <td data-label="Status">
                      <RbacStatus status={user.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </RbacTableRegion>
        )}
      </section>
      <Pagination label="Users pagination" pagination={model.pagination} />
    </RbacManagement>
  );
}
