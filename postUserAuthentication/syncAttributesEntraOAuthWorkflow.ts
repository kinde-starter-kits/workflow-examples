/** 
 * This workflow maps user claims from Microsoft Entra ID (OAuth2 / OpenID Connect)
 * into Kinde custom user properties.
 *
 * It runs automatically after a user authenticates with your Entra ID connection
 * and keeps user data in Kinde in sync with attributes in Azure AD.
 *
 * Setup steps:
 *
 * 1. In your Microsoft Entra ID app registration, configure the user attributes (claims)
 *    you want included in the ID token.
 *
 * 2. In Kinde, create matching custom user property keys to store these values.
 *
 * 3. Create a Machine-to-Machine (M2M) application in Kinde with the following scope enabled:
 *       • update:user_properties
 *
 *    Then, in your workflow’s Environment Variables, configure the following (values from the M2M app):
 *       • KINDE_WF_M2M_CLIENT_ID
 *       • KINDE_WF_M2M_CLIENT_SECRET    ← mark this variable as sensitive
 *
 *
 * 4. Deploy this workflow. Each time a user signs in through your Entra ID OAuth2 connection,
 *    the workflow will:
 *       • read the claims from the ID token
 *       • map them to your configured Kinde user properties
 *       • optionally capture Entra ID groups
 *       • and record a timestamp of the last synchronization.
 *
 * Once configured, this provides a live attribute-mapping bridge between Microsoft Entra ID
 * and your Kinde user profiles.
 *
 * Trigger: user:post_authentication
 */


import {
  WorkflowSettings,
  WorkflowTrigger,
  createKindeAPI,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
  id: "mapEntraIdClaims",
  name: "MapEntraIdClaims",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.env": {},
    url: {},
    "kinde.mfa": {}
  },
};

export default async function mapEntraIdClaimsWorkflow(
  event: any
) {
  const provider = event.context?.auth?.provider;
  const protocol = provider?.protocol || "";

  console.log("Event data:", JSON.stringify(event, null, 2));

  // Only process OAuth2 connections from Entra ID (Microsoft)
  if (protocol !== "oauth2") {
    console.log("Not an OAuth2 authentication, skipping claims mapping");
    return;
  }

  // Check if this is a Microsoft/Entra ID connection
  const providerName =
    provider?.provider?.toLowerCase() ||
    "";

  if (
    !providerName.includes("microsoft") &&
    !providerName.includes("entra") &&
    !providerName.includes("azure") &&
    !providerName.includes("azure_ad")
  ) {
    console.log(
      `Connection ${providerName} is not a Microsoft/Entra ID connection, skipping`
    );
    return;
  }

  const userId = event.context?.user?.id;
  console.log(`Processing Entra ID OAuth2 claims for user: ${userId}`);

  // Extract claims
  const claims = provider?.data?.idToken?.claims || {};
  console.log("Raw claims received:", claims);

  // Map of Entra ID claims -> Kinde properties
  // Some are examples; adjust based on your needs
  const claimMappings: Record<string, string> = {
    given_name: "kp_usr_first_name",
    family_name: "kp_usr_last_name",
    email: "kp_usr_email",
    name: "kp_usr_display_name",
    preferred_username: "kp_usr_username",
    oid: "entra_object_id",
    tid: "entra_tenant_id",
    upn: "entra_upn",
    unique_name: "entra_unique_name",
    jobTitle: "job_title",
    department: "department",
    officeLocation: "office_location",
    mobilePhone: "mobile_phone",
    businessPhones: "business_phones",
    uti: "kp_usr_city",
    ctry: "country",
    postalCode: "postal_code",
    state: "state",
    streetAddress: "street_address",
    companyName: "company_name",
    employeeId: "employee_id",
  };

  const propertiesToUpdate: Record<string, string> = {};

  // Map claims to properties
  for (const [claimName, propertyKey] of Object.entries(claimMappings)) {
    const claimValue = claims[claimName];
    if (claimValue) {
      propertiesToUpdate[propertyKey] = Array.isArray(claimValue)
        ? claimValue.join(", ")
        : String(claimValue);
      console.log(
        `Mapping claim ${claimName} -> ${propertyKey}: ${propertiesToUpdate[propertyKey]}`
      );
    }
  }

  // Add groups if present
  if (Array.isArray(claims.groups)) {
    propertiesToUpdate["entra_groups"] = claims.groups.join(", ");
  }

  // Always store last sync timestamp
  propertiesToUpdate["entra_last_sync"] = new Date().toISOString();

  // Nothing to update
  if (Object.keys(propertiesToUpdate).length === 0) {
    console.log("No properties to update");
    return;
  }

  // Create the Kinde API client (uses your M2M credentials)
  const kindeAPI = await createKindeAPI(event);

  try {
    await kindeAPI.patch({
      endpoint: `users/${userId}/properties`,
      params: { properties: propertiesToUpdate },
    });

    console.log(
      `Successfully updated ${Object.keys(propertiesToUpdate).length} properties for user ${userId}`
    );
  } catch (error) {
    console.error("Error updating user properties:", error);
  }

  console.log(`Completed Entra ID claims mapping for user ${userId}`);
}
