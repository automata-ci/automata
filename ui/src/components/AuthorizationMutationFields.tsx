interface AuthorizationMutationCapability {
  readonly csrfToken: string;
  readonly expectedAuthorizationRevision: string;
}

export function AuthorizationMutationFields({
  capability,
}: {
  readonly capability: AuthorizationMutationCapability;
}) {
  return (
    <>
      <input name="csrf_token" type="hidden" value={capability.csrfToken} />
      <input
        name="expected_authorization_revision"
        type="hidden"
        value={capability.expectedAuthorizationRevision}
      />
    </>
  );
}
