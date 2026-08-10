import type { ReactNode } from "react";
import type { DirectBindingListPageModel } from "../models";
import { Pagination } from "../components/Pagination";
import { enforceRbacReasonValidity } from "../components/rbacInputConstraints";
import {
  RbacManagement,
  RbacMutationFields,
  RbacScope,
  RbacStatus,
  RbacTableRegion,
} from "../components/RbacManagement";

export interface DirectBindingPageProps {
  readonly model: DirectBindingListPageModel;
  readonly shellUtility?: ReactNode;
}

export function DirectBindingPage({ model, shellUtility }: DirectBindingPageProps) {
  return (
    <RbacManagement
      heading={model.heading}
      managementNav={model.managementNav}
      notice={model.notice}
      shell={model.shell}
      shellUtility={shellUtility}
      summary={model.summary}
    >
      {model.grant === null ? (
        <p className="rbac-read-only rbac-read-only--standalone" role="note">
          {model.readOnlyReason === "options-overflow"
            ? "The complete grant choices exceed the browser limit. Narrow tenant resources before granting here."
            : model.readOnlyReason === "no-options"
              ? "No active user and role choices are currently available for a direct grant."
              : model.readOnlyReason === "not-authorized"
                ? "Direct grants aren’t available with your current access."
                : "Direct grant choices are temporarily unavailable."}
        </p>
      ) : (
        <section className="panel rbac-panel" aria-labelledby="grant-binding-heading">
          <div className="panel__heading">
            <h2 id="grant-binding-heading">Grant direct role</h2>
          </div>
          <form action={model.grant.action} className="rbac-native-form" method="post">
            <RbacMutationFields
              csrfToken={model.grant.csrfToken}
              expectedAuthorizationRevision={model.grant.expectedAuthorizationRevision}
            />
            <label>
              User
              <select name="principal_id" required>
                {model.grant.principals.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </label>
            <label>
              Role
              <select name="role_id" required>
                {model.grant.roles.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </label>
            <label>
              Scope
              <select name="scope" required>
                {model.grant.scopes.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </label>
            <label>
              <span id="direct-binding-valid-until-label">Valid until (UTC)</span>
              <small id="direct-binding-valid-until-hint">
                Leave blank for no expiry.
              </small>
              <input
                aria-describedby="direct-binding-valid-until-hint"
                aria-labelledby="direct-binding-valid-until-label"
                name="valid_until"
                step="60"
                type="datetime-local"
              />
            </label>
            <button className="button" type="submit">Grant role</button>
          </form>
        </section>
      )}
      <section
        aria-labelledby={model.bindings.length === 0 ? "bindings-heading" : undefined}
        className="panel rbac-panel"
      >
        <div className="panel__heading">
          <h2 id="bindings-heading">Role bindings</h2>
          <span>{model.pagination.label}</span>
        </div>
        <p className="rbac-guidance">
          Provider-observed mappings remain read-only evidence; only active direct
          assignments can be revoked here.
        </p>
        {model.bindings.length === 0 ? (
          <p className="rbac-empty">No role bindings are available with your current access.</p>
        ) : (
          <RbacTableRegion labelledBy="bindings-heading">
            <table className="rbac-table rbac-table--bindings">
              <caption className="sr-only">
                Direct and provider-observed role bindings with exact scopes
              </caption>
              <thead>
                <tr>
                  <th scope="col">User</th>
                  <th scope="col">Role</th>
                  <th scope="col">Scope</th>
                  <th scope="col">Source</th>
                  <th scope="col">Status</th>
                  <th scope="col">Valid until</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {model.bindings.map((binding) => (
                  <tr id={binding.id} key={binding.id} tabIndex={-1}>
                    <th data-label="User" scope="row">
                      <a className="rbac-primary-link" href={binding.principal.href}>
                        {binding.principal.label}
                      </a>
                    </th>
                    <td data-label="Role">
                      <a className="rbac-primary-link" href={binding.role.href}>
                        {binding.role.label}
                      </a>
                      <small>{binding.role.name}</small>
                    </td>
                    <td data-label="Scope"><RbacScope scope={binding.scope} /></td>
                    <td data-label="Source">
                      {binding.source === "direct" ? "Direct" : "Provider observed"}
                    </td>
                    <td data-label="Status">
                      <RbacStatus status={binding.status} />
                    </td>
                    <td data-label="Valid until">
                      {binding.validUntil === null
                        ? "No expiry"
                        : (
                            <time dateTime={binding.validUntil.iso}>
                              {binding.validUntil.label}
                            </time>
                          )}
                    </td>
                    <td data-label="Action">
                      {binding.revoke === null ? (
                        <span className="rbac-muted-action">Read-only</span>
                      ) : (
                        <form
                          action={binding.revoke.action}
                          className="rbac-inline-revoke"
                          method="post"
                        >
                          <RbacMutationFields
                            csrfToken={binding.revoke.csrfToken}
                            expectedAuthorizationRevision={
                              binding.revoke.expectedAuthorizationRevision
                            }
                          />
                          <input
                            name="expected_revision"
                            type="hidden"
                            value={binding.revoke.expectedRevision}
                          />
                          <label>
                            <span className="sr-only">Revocation reason</span>
                            <input
                              aria-label={`Reason for revoking ${binding.role.label} from ${binding.principal.label}`}
                              maxLength={1024}
                              name="reason"
                              onInput={(event) =>
                                enforceRbacReasonValidity(event.currentTarget)
                              }
                              placeholder="Reason"
                              required
                            />
                          </label>
                          <button
                            aria-label={`Revoke ${binding.role.label} role from ${binding.principal.label} for ${binding.scope.label}`}
                            className="button button--compact button--danger"
                            type="submit"
                          >
                            Revoke
                          </button>
                        </form>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </RbacTableRegion>
        )}
      </section>
      <Pagination label="Role bindings pagination" pagination={model.pagination} />
    </RbacManagement>
  );
}
