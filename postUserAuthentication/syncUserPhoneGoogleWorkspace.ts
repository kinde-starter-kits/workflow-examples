import {
    onPostAuthenticationEvent,
    WorkflowSettings,
    WorkflowTrigger,
    getEnvironmentVariable,
    createKindeAPI,
} from "@kinde/infrastructure";

// This workflow requires you to set up the Kinde Management API,
// a Google Workspace SAML attribute mapping for the phone number,
// and a user property in Kinde to store the phone value.
//
// You can do this by going to the Kinde dashboard.
//
// Create an M2M application with the following scopes enabled:
// * update:user_properties
//
// In Settings -> Environment variables set up the following variables with the
// values from the M2M application you created above and the Google Workspace connection ID:
//
// * KINDE_WF_M2M_CLIENT_ID
// * KINDE_WF_M2M_CLIENT_SECRET - Ensure this is setup with sensitive flag
//   enabled to prevent accidental sharing
// * GOOGLE_WORKSPACE_CONNECTION_ID
//
// In your Google Admin Console, go to:
// Apps -> Web and mobile apps -> (your SAML app) -> SAML Attribute mapping
// Add an attribute with:
// * Name: phone   (exact string expected by this workflow; case-insensitive)
// * Value: the user’s phone field
//   - If your attribute name is different, update the `googlePhoneAttributeName` value in the code.
//
// In Kinde, create a user property key to store the phone number:
// * Key: phone_number
//   - If you use a different key, change `phonePropertyKey` in the code.

export const workflowSettings: WorkflowSettings = {
    id: "postAuthentication",
    name: "GoogleWorkspacePhoneSync",
    failurePolicy: {
        action: "stop",
    },
    trigger: WorkflowTrigger.PostAuthentication,
    bindings: {
        "kinde.env": {},
        url: {},
    },
};

type SamlValue = { value?: string };
type SamlAttribute = { name?: string; values?: SamlValue[] };
type SamlAttributeStatement = { attributes?: SamlAttribute[] };

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    const connectionId = event.context.auth.connectionId;
    const googleWorkspaceConnectionId = getEnvironmentVariable("GOOGLE_WORKSPACE_CONNECTION_ID")?.value;
    if (!googleWorkspaceConnectionId || connectionId !== googleWorkspaceConnectionId) return;
    const attributeStatements =
        event.context.auth.provider?.data?.assertion
            ?.attributeStatements as SamlAttributeStatement[] | undefined;

    if (!attributeStatements?.length) return;

    const googlePhoneAttributeName = "phone";

    const phoneAttr = attributeStatements
        .flatMap((s) => s.attributes ?? [])
        .find((a) => a.name?.toLowerCase().trim() === googlePhoneAttributeName);

    const phoneValue = phoneAttr?.values?.[0]?.value?.trim() || null;
    if (!phoneValue) return;

    const kindeAPI = await createKindeAPI(event);
    const userId = event.context.user.id;

    const phonePropertyKey = "phone_number";

    await kindeAPI.put({
        endpoint: `users/${userId}/properties/${phonePropertyKey}?value=${encodeURIComponent(phoneValue)}`
    });
}