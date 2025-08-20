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
// If you choose different keys, update the corresponding property key constants in the code:
// * `phonePropertyKey`
// * `userTypePropertyKey`
// * `groupsPropertyKey`
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

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    const connectionId = event.context.auth.connectionId;
    const oktaConnectionId = getEnvironmentVariable("OKTA_CONNECTION_ID")?.value;
    if (!oktaConnectionId || connectionId !== oktaConnectionId) return;

    const attributeStatements =
        event.context.auth.provider?.data?.assertion
            ?.attributeStatements as SamlAttributeStatement[] | undefined;
    if (!attributeStatements?.length) return;

    const attrs: SamlAttribute[] = attributeStatements.flatMap((s) => s.attributes ?? []);
    const findAttr = (names: string[]) =>
        attrs.find((a) => {
            const n = a.name?.toLowerCase().trim() ?? "";
            return names.some((want) => n === want.toLowerCase());
        });

    const phoneAttrNames = ["phone_number"];
    const userTypeAttrNames = ["user_type"];
    const groupsAttrNames = ["groups"];

    const getFirstString = (a?: SamlAttribute | null) =>
        (a?.values?.[0]?.value ?? "").toString().trim() || null;

    const getAllStrings = (a?: SamlAttribute | null) =>
        (a?.values ?? [])
            .map((v) => (v.value ?? "").toString().trim())
            .filter(Boolean);

    const phoneValue = getFirstString(findAttr(phoneAttrNames));
    const userTypeValue = getFirstString(findAttr(userTypeAttrNames));

    const groupsArray = getAllStrings(findAttr(groupsAttrNames));
    const groupsValue = groupsArray.length ? groupsArray.join(",") : null;

    if (!phoneValue && !userTypeValue && !groupsValue) return;

    const kindeAPI = await createKindeAPI(event);
    const userId = event.context.user.id;

    const phonePropertyKey = "phone_number";
    const userTypePropertyKey = "user_type";
    const groupsPropertyKey = "groups";

    const properties: Record<string, string> = {};
    if (phoneValue) properties[phonePropertyKey] = phoneValue;
    if (userTypeValue) properties[userTypePropertyKey] = userTypeValue;
    if (groupsValue) properties[groupsPropertyKey] = groupsValue;

    await kindeAPI.patch({
        endpoint: `users/${userId}/properties`,
        params: { properties },
    });
}