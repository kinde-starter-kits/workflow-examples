import {
    onPostAuthenticationEvent,
    WorkflowSettings,
    WorkflowTrigger,
    createKindeAPI,
} from "@kinde/infrastructure";

// This workflow syncs user attributes and groups from a SAML assertion into Kinde custom user properties.
// It works with any SAML connection, as long as attributes and groups are exposed in the SAML response.
//
// Setup steps:
//
// 1. In your Identity Provider (IdP), configure SAML attribute statements / group attribute statements
//    to send the attributes you want to sync.
//
// 2. In Kinde, create custom user property keys to store these attributes:
//    * phone_number
//    * user_type
//    * groups
//
//    Note: In the `attributeSyncConfig` object below, update the `samlNames` array
//    for each property to include all possible attribute names your IdP(s) might send
//    (e.g., ["phone_number", "phone", "mobilephone"]).
//
// 3. Create an M2M application in Kinde with the following scope enabled:
//    * update:user_properties
//
//    In Settings -> Environment variables, configure the following (values from your M2M application):
//    * KINDE_WF_M2M_CLIENT_ID
//    * KINDE_WF_M2M_CLIENT_SECRET  (mark as sensitive)
//
// 4. Ensure the properties are included in tokens by toggling OFF the “Private” option in their settings.
//    Then, in the Application settings in Kinde, add them under **Token customization**.
//
// Once configured, this workflow will run after authentication, read the attributes from the SAML assertion,
// and sync them into Kinde so they can be used in tokens or elsewhere.

export const workflowSettings: WorkflowSettings = {
    id: "postAuthentication",
    name: "SamlAttributesSync",
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
    {
        samlNames: ["phone_number", "phone", "mobilephone"],
        kindeKey: "phone_number",
        multiValue: false,
    },
    {
        samlNames: ["user_type", "usertype"],
        kindeKey: "user_type",
        multiValue: false,
    },
    {
        samlNames: ["groups", "group"],
        kindeKey: "groups",
        multiValue: true,
    },
];

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    const protocol = event.context?.auth?.provider?.protocol;
    if (!protocol || protocol !== "saml") return;

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
        let foundValues: string[] | undefined;
        for (const name of config.samlNames) {
            const values = samlAttributesMap.get(name);
            if (values && values.length > 0) {
                foundValues = values;
                break;
            }
        }

        if (foundValues) {
            if (config.multiValue) {
                propertiesToUpdate[config.kindeKey] = foundValues.join(",");
            } else {
                propertiesToUpdate[config.kindeKey] = foundValues[0];
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