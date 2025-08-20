import {
    onPostAuthenticationEvent,
    WorkflowSettings,
    WorkflowTrigger,
    getEnvironmentVariable,
    createKindeAPI,
} from "@kinde/infrastructure";

// This workflow requires you to set up the Kinde Management API,
// Okta attribute statements for user attributes (mobilePhone and userType),
// and a group attribute statement for groups.
//
// You can do this by going to the Kinde dashboard.
//
// Create an M2M application with the following scopes enabled:
// * update:user_properties
//
// In Settings -> Environment variables set up the following variables with the
// values from the M2M application you created above and the Okta connection ID:
//
// * KINDE_WF_M2M_CLIENT_ID
// * KINDE_WF_M2M_CLIENT_SECRET - Ensure this is setup with sensitive flag
//   enabled to prevent accidental sharing
// * OKTA_CONNECTION_ID
//
// In your Okta Admin Console, go to:
// Applications -> (your Kinde SAML app) -> General -> SAML Settings -> Edit -> Attribute Statements / Group Attribute Statements
//
// Add the following attribute statements:
// * Name: phone_number   (exact string expected by this workflow; case-insensitive)
// * Value: user.mobilePhone
// * Name: user_type      (exact string expected by this workflow; case-insensitive)
// * Value: user.userType
//
// Add a group attribute statement to include the user’s groups:
// * Name: groups        (exact string expected by this workflow; case-insensitive)
// * Filter: Matches regex .*
//
// In Kinde, create custom user property keys to store these attributes:
// * phone_number   (for mobilePhone)
// * user_type      (for userType)
// * groups         (for groups)
//
// If you use different SAML attribute names or Kinde property keys,
// update the `attributeSyncConfig` object in the code below.
//
// Each object in the array defines a mapping:
// - `samlName`: The attribute name from the Okta SAML assertion (case-insensitive).
// - `kindeKey`: The corresponding user property key in Kinde.
// - `multiValue`: Set to `true` if the attribute can have multiple values (like groups),
//   which will be joined by a comma.
//
// Important: when creating these properties, make sure the **“Private” option is toggled off**
// so they are included in tokens.
//
// To add these properties to tokens:
// 1. Open the relevant application from the Home screen or go to Settings > Applications.
// 2. Select **View details**.
// 3. Select **Tokens**.
// 4. Scroll to the **Token customization** section.
// 5. Select **Customize** on the relevant token type (Access token or ID token).
// 6. In the Customize dialog, select the properties (`phone_number`, `user_type`, `groups`).
// 7. Select **Save**.

export const workflowSettings: WorkflowSettings = {
    id: "postAuthentication",
    name: "OktaAttributesSync",
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

const attributeSyncConfig = [
    { samlName: "phone_number", kindeKey: "phone_number", multiValue: false },
    { samlName: "user_type", kindeKey: "user_type", multiValue: false },
    { samlName: "groups", kindeKey: "groups", multiValue: true },
];

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    const connectionId = event.context.auth.connectionId;
    const oktaConnectionId = getEnvironmentVariable("OKTA_CONNECTION_ID")?.value;
    if (!oktaConnectionId || connectionId !== oktaConnectionId) return;

    const attributeStatements =
        event.context.auth.provider?.data?.assertion
            ?.attributeStatements as SamlAttributeStatement[] | undefined;
    if (!attributeStatements?.length) return;

    const samlAttributesMap = (attributeStatements ?? [])
        .flatMap((statement) => statement.attributes ?? [])
        .reduce((acc, attr) => {
            const name = attr.name?.toLowerCase().trim();
            if (name) {
                const values = (attr.values ?? [])
                    .map((v) => v.value?.trim())
                    .filter((v): v is string => !!v);
                if (values.length > 0) {
                    acc.set(name, values);
                }
            }
            return acc;
        }, new Map<string, string[]>());

    const propertiesToUpdate: Record<string, string> = {};

    for (const config of attributeSyncConfig) {
        const values = samlAttributesMap.get(config.samlName);
        if (values && values.length > 0) {
            if (config.multiValue) {
                propertiesToUpdate[config.kindeKey] = values.join(",");
            } else {
                propertiesToUpdate[config.kindeKey] = values[0];
            }
        }
    }

    if (Object.keys(propertiesToUpdate).length === 0) return;

    const kindeAPI = await createKindeAPI(event);
    const userId = event.context.user.id;

    await kindeAPI.patch({
        endpoint: `users/${userId}/properties`,
        params: { properties: propertiesToUpdate },
    });
}