import {
  onTokensGenerationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  accessTokenCustomClaims,
  idTokenCustomClaims,
  createKindeAPI,
} from "@kinde/infrastructure";

/**
 * Add IdP Claims to Tokens Workflow
 * 
 * This workflow reads IdP claims that were captured during authentication
 * (stored in the `idp_claims` user property) and adds them to tokens.
 * 
 * This workflow works in conjunction with CaptureIdpClaimsWorkflow:
 * 1. CaptureIdpClaimsWorkflow (PostAuthentication) - captures IdP claims and stores them
 * 2. This workflow (TokensGeneration) - reads stored claims and adds them to tokens
 * 
 * Benefits:
 * - Automatically includes ALL IdP claims in tokens (no hardcoding needed)
 * - Claims persist across token refreshes
 * - Easy to customize which claims go into which tokens
 * - Works with any OAuth2/OIDC provider
 * 
 * Setup:
 * 1. Create a Machine-to-Machine (M2M) application in Kinde with this scope:
 *    - read:user_properties
 * 
 * 2. Add these environment variables to your workflow:
 *    - KINDE_WF_M2M_CLIENT_ID (from your M2M app)
 *    - KINDE_WF_M2M_CLIENT_SECRET (from your M2M app, mark as sensitive)
 * 
 * 3. Deploy the CaptureIdpClaimsWorkflow first (PostAuthentication trigger)
 * 4. Deploy this workflow (TokensGeneration trigger)
 * 5. Authenticate via a social connection to test
 * 6. Your tokens will include all captured IdP claims with "idp_" prefix
 * 
 * Example token claims after deployment:
 * - idp_email: user's email from IdP
 * - idp_name: user's full name from IdP
 * - idp_sub: user's unique ID at the IdP
 * - idp_picture: user's profile picture URL
 * - Plus any other claims provided by the IdP
 * 
 * Note: This workflow runs on EVERY token generation, not just initial authentication.
 * The claims are fetched from stored user properties via Management API.
 * 
 * Trigger: user:tokens_generation
 */

export const workflowSettings: WorkflowSettings = {
  id: "addIdpClaimsToTokens",
  name: "Add IdP Claims to Tokens",
  trigger: WorkflowTrigger.UserTokenGeneration,
  failurePolicy: {
    action: "stop",
  },
  bindings: {
    "kinde.accessToken": {
      audience: [],
    },
    "kinde.idToken": {},
    "kinde.env": {},
    "url": {},
  },
};

export default async function handleTokensGeneration(event: onTokensGenerationEvent) {
  // Get user ID from the event
  const userId = event.user?.id || event.context?.user?.id;

  if (!userId) {
    console.error("User ID is missing from event");
    return;
  }

  // Create the Kinde API client to fetch user properties
  const kindeAPI = await createKindeAPI(event);

  // Fetch user properties via Management API
  let userProperties: Record<string, any> = {};
  
  try {
    const propertiesResponse = await kindeAPI.get({
      endpoint: `users/${userId}/properties`,
    });

    // The response structure is: { data: { properties: [...] } }
    const properties = propertiesResponse?.data?.properties || propertiesResponse?.properties;

    // Convert properties array to a key-value object
    if (properties && Array.isArray(properties)) {
      for (const prop of properties) {
        userProperties[prop.key] = prop.value;
      }
    }
  } catch (error: any) {
    console.error("Failed to fetch user properties:", error?.message || error);
    return;
  }

  // Check if the idp_claims property exists
  if (!userProperties.idp_claims) {
    // User hasn't authenticated via IdP or CaptureIdpClaimsWorkflow isn't deployed
    return;
  }

  // Parse the JSON from the idp_claims property
  let idpClaims: Record<string, any>;
  try {
    idpClaims = JSON.parse(userProperties.idp_claims as string);
  } catch (error) {
    console.error("Failed to parse idp_claims property:", error);
    return;
  }

  // Initialize token custom claims with dynamic types
  const accessToken = accessTokenCustomClaims<Record<string, any>>();
  const idToken = idTokenCustomClaims<Record<string, any>>();

  // Add all IdP claims to tokens with "idp_" prefix
  // Skip metadata fields (those starting with "_")
  let claimsAdded = 0;
  
  for (const [claimName, claimValue] of Object.entries(idpClaims)) {
    // Skip metadata fields like _provider and _last_updated
    if (claimName.startsWith('_')) {
      continue;
    }

    // Add to both access and ID tokens with "idp_" prefix
    const tokenClaimName = `idp_${claimName}`;
    accessToken[tokenClaimName] = claimValue;
    idToken[tokenClaimName] = claimValue;
    
    claimsAdded++;
  }

  if (claimsAdded > 0) {
    console.log(`Added ${claimsAdded} IdP claims to tokens (provider: ${idpClaims._provider || 'unknown'})`);
  }
}

