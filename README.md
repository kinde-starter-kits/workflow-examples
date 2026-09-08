# ⚙️ Kinde Workflow examples

This repository contains example **JavaScript/TypeScript workflows** for [Kinde](https://kinde.com), showing how to run custom code at key points in the **authentication flow** using **Kinde Workflows**.

## 🧠 What Are Kinde Workflows?

Kinde Workflows let you run custom JavaScript/TypeScript logic **during the authentication process**, giving you full control over:

- User onboarding
- Role and permission assignment
- Profile enrichment
- Custom validation or access control
- Third-party service integration

All code is executed **server-side on Kinde**, meaning you don’t need to host or deploy anything yourself.

## 🧪 Example Use Cases

This repo includes examples for:

| Folder | Triggered when |
| --- | --- |
| `/existingPassword` | a user enters their password |
| `/m2mToken` | an M2M token is requested |
| `/newPassword` | a user sets a new password (including reset) |
| `/postUserAuthentication` | a user completes single factor authentication (e.g Google auth) |
| `/preMFA` | before checking if MFA is required |
| `/userTokens` | ID and access tokens are generated |
| `/planSelection` | A user tries to change plan |
| `/planCancellationRequest` | A user requests to cancel their subscription |

### Examples

- [Block disposable emails](https://github.com/kinde-starter-kits/workflow-examples/blob/main/preUserRegistration/blockDisposableEmails.ts) - Allows you to block users from signing up with disposable email domains.
- [Drip feed migration](https://github.com/kinde-starter-kits/workflow-examples/blob/main/existingPassword/dripFeedMigrationWorkflow.ts) - Shows how to check a password against an external database before creating the user in Kinde.
- [Sync passwords to another system](https://github.com/kinde-starter-kits/workflow-examples/blob/main/newPassword/securelySyncPasswordWorkflow.ts) - Use encryption keys to securely keep passwords in sync between systems.
- [Custom password validation](https://github.com/kinde-starter-kits/workflow-examples/blob/main/newPassword/customPasswordValidationWorkflow.ts) - Shows how to validate a password against your own rules.
- [Sync new user data to Hubspot](https://github.com/kinde-starter-kits/workflow-examples/blob/main/postUserAuthentication/syncNewUserToHubspotWorkflow.ts) - Send user data and UTM tags to Hubspot when a new user record is created in Kinde.
- [TrustPath impossible travel](https://github.com/kinde-starter-kits/workflow-examples/blob/main/postUserAuthentication/impossibleTravelWorkflow.ts) - Evaluate user login risk using TrustPath's API by checking for "impossible travel" patterns based on IP and recent login activity. If high risk is detected, access is blocked proactively.
- [Set a grace period for MFA](https://github.com/kinde-starter-kits/workflow-examples/blob/main/preMFA/gracePeriodWorkflow.ts) - Don't ask for MFA for a set period of time after a user has logged in.
- [Add custom claims to access token](https://github.com/kinde-starter-kits/workflow-examples/blob/main/userTokens/customClaimsAccessTokenWorkflow.ts) - Call an external API to get data to add as custom claims to the user access token.
- [Map M2M applications to organizations](https://github.com/kinde-starter-kits/workflow-examples/blob/main/m2mToken/mapOrgToM2MApplicationWorkflow.ts) - Shows how to map M2M applications to organizations. Useful if using Kinde for B2B API key management
- [Deny plan change](https://github.com/kinde-starter-kits/workflow-examples/blob/main/planSelection/denyPlanChangeWorkflow.ts) - Prevent a user from changing plans. Useful if they aren't eligible to if in breach of limits
- [Deny plan cancellation](https://github.com/kinde-starter-kits/workflow-examples/blob/main/planCancellationRequest/denyPlanCancellation.ts) - Prevent a user from cancelling their plan. Useful if you need to do manual deprovisioning
- [Check IP with AbuseIPDB](https://github.com/kinde-starter-kits/workflow-examples/blob/main/postUserAuthentication/checkIPWithAbuseIPDBWorkflow.ts) - Checks IP of user logging in with AbuseIPDB and blocks login if abuse confidence rating is too high.
- [Include billing info in user tokens](https://github.com/kinde-starter-kits/workflow-examples/blob/main/userTokens/addBillingDetailsToTokensB2C.ts) - Fetches a user’s billing information during token generation and adds it to the user tokens as a billingDetails custom claim. 
- [Track Organization seat usage](https://github.com/kinde-starter-kits/workflow-examples/blob/main/billing/trackOrgSeatUsageWorkflow.ts) - Updates metered seat usage for B2B SaaS organizations in Kinde when a new user joins. Ensures accurate per-user billing by incrementing the 'user' feature count after authentication.

Each example includes:

- A full `.ts` workflow file
- Setup or config notes
- A brief explanation of what it does

## 🔧 How to use these examples

1. Open an example file and explore the code.

2. Use it as a starting point for your own workflows.

## Base template

If you're looking for somewhere to start then try out the [base workflow template](https://github.com/kinde-starter-kits/workflow-base-template)

> 💡 Kinde runs workflows in a secure, isolated environment. All workflows should be deterministic and performant.

📦 Requirements

- A Kinde account
- Basic knowledge of JavaScript or TypeScript

🤝 Contributing

Have a great idea or an awesome use case? Open a PR! Contributions are welcome.
