import {
  onPostAuthenticationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  accessTokenCustomClaims,
  idTokenCustomClaims,
} from "@kinde/infrastructure";

// This workflow extracts claims from social identity provider (IdP) tokens and adds them
// as custom claims to Kinde's access and ID tokens. This allows you to preserve additional
// user information from the social provider that may not be captured by Kinde by default.
//
// IMPORTANT: This is a simplified example that extracts only the email claim to demonstrate
// the pattern. You can easily extend this to extract additional claims such as name, picture,
// email_verified, locale, or provider-specific claims (e.g., Google Workspace domain).
// See the comments in the code for available claims you can extract.
//
// This workflow supports OAuth2 / OpenID Connect (OIDC) providers such as:
// * Google
// * Microsoft / Azure AD
// * Any OIDC-compliant provider
//
// Note: Pure OAuth 2.0 providers (like GitHub) that do not issue JWT ID tokens will not
// have claims available in the provider.data.idToken object.
//
// Setup steps:
//
// 1. Configure your social connection in Kinde (e.g., Google, Microsoft).
//
// 2. This workflow will automatically extract claims from the IdP's ID token during authentication.
//
// 3. The following claims are commonly available from OIDC providers:
//    * sub - The user's unique identifier at the IdP
//    * email - The user's email address
//    * name - The user's full name
//    * picture - URL to the user's profile picture
//    * email_verified - Whether the email has been verified by the IdP
//    * given_name / family_name - First and last name
//    * locale - User's preferred language/locale
//
// 4. Provider-specific claims may also be available:
//    * Google: hd (hosted domain for Google Workspace users)
//    * Microsoft: tid (tenant ID for Azure AD users)
//
// Once configured, this workflow will run after a user authenticates via a social connection,
// and the custom claims will be included in the tokens returned to your application.

export const workflowSettings: WorkflowSettings = {
  id: "postAuthentication",
  name: "IdpTokenWorkflow",
  trigger: WorkflowTrigger.PostAuthentication,
  failurePolicy: {
    action: "stop",
  },
  bindings: {
    "kinde.accessToken": {}, // Required to modify access token claims
    "kinde.idToken": {}, // Required to modify ID token claims
  },
};

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
  const provider = event.context?.auth?.provider;

  // Only process OAuth2/OIDC social connections
  if (!provider || provider.protocol !== "oauth2") {
    return;
  }

  const idTokenClaims = provider.data?.idToken?.claims;

  // If no ID token claims are available, skip processing
  // This is expected for pure OAuth 2.0 providers like GitHub
  if (!idTokenClaims) {
    return;
  }

  // Set the types for the custom claims we want to add
  const accessToken = accessTokenCustomClaims<{
    idp_email: string;
  }>();

  // Add the user's email from the IdP to the access token
  if (idTokenClaims.email) {
    accessToken.idp_email = idTokenClaims.email as string;
  }

  // You can also extract other claims from the IdP token:
  // * idTokenClaims.sub - User's unique ID at the IdP
  // * idTokenClaims.name - User's full name
  // * idTokenClaims.picture - Profile picture URL
  // * idTokenClaims.email_verified - Email verification status
  // * idTokenClaims.hd - Google Workspace hosted domain
  // * idTokenClaims.tid - Microsoft tenant ID
}
