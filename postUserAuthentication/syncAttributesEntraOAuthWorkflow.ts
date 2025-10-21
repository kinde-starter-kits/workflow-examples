/**
 * This workflow maps user claims from Microsoft Entra ID (OAuth2 / OpenID Connect)
 * into Kinde custom user properties.
 *
 * It runs automatically after a user authenticates with your Entra ID connection
 * and keeps user data in Kinde in sync with attributes in Azure AD.
 *
 * Setup steps:
 *
 * 1. In your Microsoft Entra ID app registration:
 *       • Configure the user attributes (claims) you want included in the ID token.
 *        
 *
 * 2. In Kinde:
 *       • Create matching **custom user property keys** for each claim you want to store.
 *         For instance, create a custom property named `usr_username` to map the Entra ID claim.
 *
 *       • To make a custom property appear in the ID token:
 *             Go to your Kinde **Application → Tokens → ID Token**
 *             and **add any custom properties** you want included (e.g., `usr_username`).
 *
 * 3. Create a Machine-to-Machine (M2M) application in Kinde with the following scope enabled:
 *       • update:user_properties
 *
 *    Then, in your workflow's Environment Variables, configure the following (values from the M2M app):
 *       • KINDE_WF_M2M_CLIENT_ID
 *       • KINDE_WF_M2M_CLIENT_SECRET    ← mark this variable as sensitive
 *
 * 4. Deploy this workflow. Each time a user signs in through your Entra ID OAuth2 connection,
 *    the workflow will:
 *       • read the claims from the ID token
 *       • map them to your configured Kinde user properties (e.g., usr_username, department, job_title)
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
    "url": {}
  },
};

export default async function mapEntraIdClaimsWorkflow(
  event: any
) {
  const provider = event.context?.auth?.provider;
  const protocol = provider?.protocol || "";


  // Only process OAuth2 connections from Entra ID (Microsoft)
  if (protocol !== "oauth2") {
    console.log("Not an OAuth2 authentication, skipping claims mapping");
    return;
  }

  // Check if this is a Microsoft/Entra ID connection using a strict whitelist
  // This might need tweaking according to your use case
  const rawProvider = provider?.provider ?? "";
  const providerName = String(rawProvider).trim().toLowerCase();
  const allowedProviders = new Set([
    "microsoft",
    "entra",
    "azure",
    "azure_ad",
    "azuread",
  ]);

  if (!allowedProviders.has(providerName)) {
    console.log(
      `Connection provider '${rawProvider}' is not an allowed Microsoft/Entra ID provider, skipping`
    );
    return;
  }

  const userId = event.context?.user?.id;

  if (!userId) {
    console.error("User ID is missing from event context");
    throw new Error("User ID is required for claims mapping");
  }

  console.log(`Processing Entra ID OAuth2 claims for user: ${userId}`);

  // Extract claims
  const claims = provider?.data?.idToken?.claims || {};

  // Map of Entra ID claims -> Kinde properties
  // Some are examples; adjust based on your needs
  const claimMappings: Record<string, string> = {
    given_name: "kp_usr_first_name",
    family_name: "kp_usr_last_name",
    email: "kp_usr_email",
    preferred_username: "usr_username",
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
        `Mapping claim ${claimName} -> ${propertyKey}`
      );
    }
  }

  // Add groups if present
  if (Array.isArray(claims.groups)) {
    propertiesToUpdate["entra_groups"] = claims.groups.join(", ");
  }

  // If there are no claim-derived properties to update, skip making an API call
  if (Object.keys(propertiesToUpdate).length === 0) {
    console.log("Nothing to update from claims; skipping property sync");
    return;
  }

  // Store last sync timestamp only when there are other updates
  propertiesToUpdate["entra_last_sync"] = new Date().toISOString();

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
    throw error;
  }

  console.log(`Completed Entra ID claims mapping for user ${userId}`);
}
