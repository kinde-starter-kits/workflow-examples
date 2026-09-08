/**
 * Capture IdP Claims Workflow
 * 
 * This workflow captures ALL claims from social identity providers (Google, Microsoft, etc.)
 * and stores them in a single user property as JSON.
 * 
 * This workflow works in conjunction with AddIdpClaimsToTokensWorkflow:
 * 1. This workflow (PostAuthentication) - captures and stores IdP claims
 * 2. AddIdpClaimsToTokensWorkflow (TokensGeneration) - reads stored claims and adds them to tokens
 * 
 * Benefits:
 * - Automatically captures all IdP claims without hardcoding specific claim names
 * - Only creates ONE property instead of many individual properties
 * - Preserves original IdP token structure and values
 * - New claims from IdP are automatically captured without code changes
 * 
 * Setup:
 * 1. Create a Machine-to-Machine (M2M) application in Kinde with these scopes:
 *    - read:properties
 *    - create:properties  
 *    - update:user_properties
 * 
 * 2. Add these environment variables to your workflow:
 *    - KINDE_WF_M2M_CLIENT_ID (from your M2M app)
 *    - KINDE_WF_M2M_CLIENT_SECRET (from your M2M app, mark as sensitive)
 * 
 * 3. Get your property category ID:
 *    - Go to Settings → Properties → Categories in Kinde dashboard
 *    - Create a category (e.g., "Identity Provider") or use an existing one
 *    - Update the PROPERTY_CATEGORY_ID constant below with your category ID
 * 
 * 4. Deploy this workflow
 * 5. Deploy the AddIdpClaimsToTokensWorkflow (companion workflow)
 * 6. Authenticate via a social connection to test
 * 
 * Supported Providers:
 * - Any OAuth2/OIDC provider (Google, Microsoft, GitHub, etc.)
 * 
 * Trigger: user:post_authentication
 */

import {
  WorkflowSettings,
  WorkflowTrigger,
  createKindeAPI,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
  id: "captureIdpClaimsJson",
  name: "Capture IdP Claims as JSON",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.env": {},
    "url": {}
  },
};

export default async function captureIdpClaimsWorkflow(event: any) {
  const provider = event.context?.auth?.provider;
  
  // Only process OAuth2/OIDC social connections
  if (!provider || provider.protocol !== "oauth2") {
    console.log("Not an OAuth2 authentication, skipping");
    return;
  }

  const idTokenClaims = provider.data?.idToken?.claims;
  
  if (!idTokenClaims) {
    console.log("No ID token claims available");
    return;
  }

  const userId = event.context?.user?.id;
  
  if (!userId) {
    console.error("User ID is missing from event context");
    throw new Error("User ID is required");
  }

  // Create the Kinde API client
  const kindeAPI = await createKindeAPI(event);

  // CONFIGURATION: Update this with your property category ID
  // Find your category ID in: Settings → Properties → Categories
  const PROPERTY_CATEGORY_ID = "Add the category ID here"; // TODO: Replace with your category ID
  const IDP_CLAIMS_PROPERTY_KEY = "idp_claims";

  // Check if the idp_claims property exists, create it if not
  let propertyExists = false;
  
  try {
    const propertiesResponse = await kindeAPI.get({
      endpoint: 'properties',
      params: {
        context: 'usr', // Filter for user properties only
      },
    });
    
    propertyExists = (propertiesResponse.properties || []).some(
      (prop: any) => prop.key === IDP_CLAIMS_PROPERTY_KEY
    );
  } catch (error) {
    console.error("Error fetching existing properties:", error);
    throw error;
  }

  // Create the property if it doesn't exist
  if (!propertyExists) {
    try {
      await kindeAPI.post({
        endpoint: 'properties',
        params: {
          key: IDP_CLAIMS_PROPERTY_KEY,
          name: "IdP Claims",
          description: "All claims from the identity provider stored as JSON",
          type: 'multi_line_text',
          context: 'usr',
          is_private: false, // Can be included in tokens if needed
          category_id: PROPERTY_CATEGORY_ID,
        },
      });
      
      console.log(`Created property: ${IDP_CLAIMS_PROPERTY_KEY}`);
    } catch (error: any) {
      console.error(`Failed to create property '${IDP_CLAIMS_PROPERTY_KEY}':`, error?.message || error);
      throw error;
    }
  }

  // Step 3: Filter out claims we don't want to store
  const ignoreClaims = new Set([
    // Standard JWT claims (not useful to store)
    'iss',        // Issuer
    'aud',        // Audience
    'exp',        // Expiration time
    'iat',        // Issued at
    'nbf',        // Not before
    'jti',        // JWT ID
    'azp',        // Authorized party
    'nonce',      // Nonce for replay protection
    'auth_time',  // Authentication time
    'at_hash',    // Access token hash
    'c_hash',     // Code hash
    
    // Microsoft-specific noise claims
    'aio',        // Microsoft internal state token (very long, not useful)
    'ver',        // Token version
    'rh',         // Microsoft refresh token hint
    'uti',        // Microsoft unique token identifier (internal use)
    'ipaddr',     // IP address (privacy concern, changes frequently)
    
    // Google-specific noise claims
    'nonce',      // Already in standard claims
    
    // Other common noise claims
    'sid',        // Session ID (changes per session)
    's_hash',     // State hash
  ]);
  
  const claimsToStore: Record<string, any> = {};
  
  for (const [claimName, claimValue] of Object.entries(idTokenClaims)) {
    if (!ignoreClaims.has(claimName) && claimValue !== null && claimValue !== undefined) {
      claimsToStore[claimName] = claimValue;
    }
  }

  // Add metadata
  claimsToStore._provider = provider.provider;
  claimsToStore._last_updated = new Date().toISOString();

  // Convert to JSON and update the user property
  const claimsJson = JSON.stringify(claimsToStore, null, 2);

  try {
    await kindeAPI.patch({
      endpoint: `users/${userId}/properties`,
      params: { 
        properties: {
          [IDP_CLAIMS_PROPERTY_KEY]: claimsJson
        }
      },
    });

    console.log(`Successfully captured ${Object.keys(claimsToStore).filter(k => !k.startsWith('_')).length} IdP claims from ${provider.provider}`);
  } catch (error: any) {
    console.error("Error updating user properties:", error?.message || error);
    throw error;
  }
}

