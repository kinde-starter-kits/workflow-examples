import {
    onPostAuthenticationEvent,
    WorkflowSettings,
    WorkflowTrigger,
    createKindeAPI,
    getEnvironmentVariable,
} from "@kinde/infrastructure";

/**
 * Workflow: Track Per-User (Seat-Based) Billing Usage in Kinde
 *
 * This workflow is designed for a standard B2B SaaS setup in Kinde, where:
 * - Organizations are billed per active user (seat-based pricing)
 * - Billing is managed by organization administrators
 * - Users can join organizations via orgCode, allowed domains, or custom invite flows
 *
 * This workflow should be triggered after user authentication (PostAuthentication event).
 * It ensures that whenever a new user is added to an organization, the metered usage for the
 * 'user' feature is updated for accurate seat-based billing.
 *
 * Prerequisites:
 * 1. Connect your Stripe account in the Kinde dashboard.
 * 2. Create and publish a per-user (seat-based) billing plan with a metered feature key 'user'.
 * 3. Assign the Billing Admin role to organization creators.
 * 4. Enable organization creation and joining via orgCode or allowed domains.
 * 5. Set up a Kinde M2M application with the following scopes:
 *   * read:organizations
 *   * create:meter_usage
 * 6. Add the following environment variables in Kinde:
 *    * KINDE_WF_M2M_CLIENT_ID
 *    * KINDE_WF_M2M_CLIENT_SECRET (set as sensitive)
 *    * KINDE_WF_BILLING_PLAN_CODE (the plan code to track, e.g. "standard-organization-plan")
 *
 * Usage:
 * - This workflow should be used to report seat usage whenever a user is added to an organization.
 * - It can be extended to handle removals or scheduled reconciliation jobs for true-up billing.
 *
 * Known limitations:
 *
 * This workflow counts seats only for users who join via the org-code self-signup
 * flow (where `orgCode` is present in `event.request.authUrlParams`). It does not
 * cover two other join paths, by design of the PostAuthentication trigger:
 *
 * 1. Domain-based auto-add — users auto-joined to an org because their email
 *    domain matches the org's allowed domains. No `orgCode` is present in the
 *    auth URL params for this flow.
 *
 * 2. Admin-invited / API-added / imported users — users added to an org by an
 *    admin via the dashboard, the management API, or a bulk import. For these
 *    users, `isNewUserRecordCreated` is `false` (Kinde already has their record),
 *    so the workflow returns early.
 *
 * The PostAuthentication trigger runs before organization access is checked
 * (per Kinde docs: "Organization access has not been checked"), so the user's
 * confirmed org memberships are not yet available via the management API at
 * this point. To capture the flows above, pair this workflow with a scheduled
 * reconciliation job that diffs actual org membership against billed seat counts.
 *
 * For more details, see the Kinde B2B SaaS billing guide.
 */

interface BillingAgreement {
    plan_code: string;
    agreement_id: string;
    [k: string]: unknown;
}

interface OrganizationBilling {
    agreements?: BillingAgreement[];
    [k: string]: unknown;
}

interface Organization {
    code?: string;
    billing?: OrganizationBilling;
    [k: string]: unknown;
}

export const workflowSettings: WorkflowSettings = {
    id: "trackOrgSeatUsage",
    name: "Track Organization Seat Usage",
    failurePolicy: {
        action: "stop",
    },
    trigger: WorkflowTrigger.PostAuthentication,
    bindings: {
        "kinde.env": {},
        "kinde.fetch": {},
        url: {},
    },
};

// The workflow code to be executed when the event is triggered
/**
 * PostAuthentication workflow handler to track seat usage for billing.
 *
 * Triggered when a user is added to the Kinde user pool for the first time (isNewUserRecordCreated).
 * Looks up the organization and plan, and updates metered usage for the 'user' feature.
 */
export default async function trackOrgSeatUsage(event: onPostAuthenticationEvent) {
    // Use optional chaining to safely access nested properties with sensible defaults
    const isNewKindeUser = event?.context?.auth?.isNewUserRecordCreated ?? false;
    const orgCode = event?.request?.authUrlParams?.orgCode;

    // Early return if required properties are missing
    if (!orgCode || !event?.context?.user?.id) {
        return;
    }

    // Only update usage if this is a new user record
    if (!isNewKindeUser) {
        console.info('Skipping metered usage update: not a new user record', { orgCode });
        return;
    }

    const kindeUserId = event.context.user.id;

    // Create Kinde Management API client
    const kindeAPI = await createKindeAPI(event);

    // Fetch organization details (including billing info)
    let orgResponse;
    try {
        orgResponse = await kindeAPI.get<Organization>({
            endpoint: `organization?code=${orgCode}&expand=billing`,
        });
    } catch (error) {
        console.error('Failed to fetch organization', {
            orgCode,
            error: (error as Error)?.message ?? error,
        });
        throw error;
    }

    if (!orgResponse?.data) {
        console.info('Skipping metered usage update: organization not found', { orgCode });
        return;
    }

    const organization = orgResponse.data;
    console.info('Organization found', { orgCode });

    const planCode = getEnvironmentVariable("KINDE_WF_BILLING_PLAN_CODE")?.value;
    if (!planCode) {
        throw new Error(
            "KINDE_WF_BILLING_PLAN_CODE environment variable is not set. " +
            "Set it to the billing plan code this workflow should track " +
            "(e.g. \"standard-organization-plan\")."
        );
    }

    // Ensure billing data exists
    if (!organization.billing || !organization.billing.agreements || organization.billing.agreements.length === 0) {
        console.info('Skipping metered usage update: no billing configured', { orgCode });
        return;
    }

    // Find the correct billing agreement for the plan
    const agreement = organization.billing.agreements.find(
        (agr: BillingAgreement) => agr.plan_code === planCode
    );

    if (!agreement) {
        console.info('Skipping metered usage update: organization not on tracked plan', { orgCode });
        return;
    }

    const billingCustomerAgreementId = agreement.agreement_id;
    const billingFeatureCode = "user"; // Must match your metered feature key

    // Update metered usage for the organization (increment seat count)
    try {
        await kindeAPI.post({
            endpoint: `billing/meter_usage`,
            params: {
                customer_agreement_id: billingCustomerAgreementId,
                billing_feature_code: billingFeatureCode,
                meter_value: "1",
                meter_type_code: "delta",
            },
        });

        console.info('Metered usage updated', { orgCode, kindeUserId });
    } catch (error) {
        console.error('Failed to update metered usage', {
            orgCode,
            kindeUserId,
            billingCustomerAgreementId,
            error: (error as Error)?.message ?? error,
        });
        throw error;
    }
}
