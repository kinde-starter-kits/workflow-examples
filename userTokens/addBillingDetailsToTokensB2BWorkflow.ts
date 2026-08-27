import { 
    createKindeAPI, 
    WorkflowSettings, 
    WorkflowTrigger,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
    id: "onTokenGenerationB2B",
    name: "AddBillingDetailsToTokensB2B",
    trigger: WorkflowTrigger.UserTokenGeneration,
    failurePolicy: {
        action: "stop"
    },
    bindings: {
        "kinde.accessToken": {},
        "kinde.idToken": {},
        "kinde.env": {}, 
        url: {} 
    }
};

// --- Types ---
interface WorkflowEvent {
    context: {
        user: {
            id: string;
        };
        organization: {
            code: string;
        };
    };
    request?: unknown;
}

interface OrganizationResponse {
    code?: string;
    name?: string;
    billing?: {
        billing_customer_id?: string;
        has_payment_details?: boolean;
        [key: string]: unknown;
    };
    [k: string]: unknown;
}

interface Entitlement {
    feature_code?: string;
    feature_name?: string;
    limit_max?: number;
    limit_min?: number;
    [k: string]: unknown;
}

interface EntitlementsResponse {
    entitlements?: Entitlement[];
    [k: string]: unknown;
}

interface Agreement {
    id?: string;
    plan_code?: string;
    expires_on?: string;
    [k: string]: unknown;
}

interface AgreementsResponse {
    agreements?: Agreement[];
    [k: string]: unknown;
}

interface OrgBillingClaim {
    customer_id: string | null;
    entitlements: Entitlement[];
    agreements: Agreement[];
}

// --- Helpers ---
const ensureArray = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);


/**
 * Token generation workflow (B2B) to add Organization billing details to tokens.
 * It identifies the current organization context, retrieves that org's billing data,
 * entitlements, and agreements, and injects them as a custom claim.
 * 
 * 
 *  Requirements:
 * 
 * 1. Create an M2M application in Kinde with these scopes:
 *      - read:organizations         (To fetch org details + billing info)
 *      - read:billing_entitlements  (To access entitlements)
 *      - read:billing_agreements    (To access agreements)
 * 
 * 2. Add M2M Client ID & Secret to Kinde Environment Variables:
 *      - KINDE_WF_M2M_CLIENT_ID 
 *      - KINDE_WF_M2M_CLIENT_SECRET (Sensitive)
 * 
 *      Docs: https://docs.kinde.com/build/env-variables/store-environment-variables/
 * 
 * 3. Execution context:
 * - This workflow expects the user to be logging into a specific organization 
 * (event.context.organization.code must be present).
 * 
 * @param event - The event object containing user and organization context.
 * @returns <void> - This function does not return a value, but the custom claims are set in the tokens 
 *
 */
export default async function OrganizationBillingWorkflow(event: WorkflowEvent) {
    try {
        console.log("Starting B2B Billing Token Workflow...");

        // [0] Validate Organization Context
        // In B2B, we only care about the org the user is currently signing into.
        const orgCode = event.context?.organization?.code;

        if (!orgCode) {
            console.warn("No Organization Code found in context. Skipping B2B billing workflow.");
            // We return early because this might be a personal/user-context login, 
            // where org billing data is irrelevant.
            return;
        }

        const kindeAPI = await createKindeAPI(event);

        // [1] Get Organization Details (with Billing expanded)
        // Endpoint: GET /api/v1/organization/{org_code}?expand=billing
        const { data: orgData } = (await kindeAPI.get({
            endpoint: `organization?code=${orgCode}&expand=billing`
        })) as { data: OrganizationResponse }; 

        const customerId = orgData?.billing?.billing_customer_id ?? null;
        let initialAgreements = ensureArray<Agreement>(orgData?.billing?.agreements);

        if (!customerId) {
            console.info(`No billing customer ID found for Org ${orgCode}. Skipping claim.`);
            return;
        }

        // [2] Fetch Entitlements & Agreements in parallel
        // Endpoints: 
        // - GET /api/v1/billing/entitlements?customer_id={id}&expand=plans
        // - GET /api/v1/billing/agreements?customer_id={id}
        const [entResp, agrResp] = await Promise.all([
            kindeAPI.get({
                endpoint: `billing/entitlements?customer_id=${customerId}&expand=plans`
            }) as Promise<{ data: EntitlementsResponse }>,
            
            // Only call agreements if we could not get it from the previous call
            initialAgreements.length === 0
            ? kindeAPI.get<AgreementsResponse>({
                endpoint: `billing/agreements?customer_id=${customerId}`
            }): Promise.resolve(null)  
        ]);

        const entitlements = ensureArray<Entitlement>(entResp?.data?.entitlements);
        const agreements =
+            agrResp?.data?.agreements ? ensureArray<Agreement>(agrResp.data.agreements) : initialAgreements;

        // [3] Construct the B2B Billing Claim Object
        const billingClaimObject: OrgBillingClaim = {
            customer_id: customerId,
            entitlements,
            agreements
        };

        // [4] Set Custom Claims
        // We inject this data into the tokens so the frontend/API can enforce limits immediately.
        kinde.accessToken.setCustomClaim("org_billing", billingClaimObject);
        kinde.idToken.setCustomClaim("org_billing", billingClaimObject);

        console.log(`Successfully set 'org_billing' claim for Org: ${orgCode}`);

    } catch (err) {
        // Log error but respect the failurePolicy (stop/fail secure)
        console.error("B2B Workflow Error:", (err as Error).message ?? err);
        throw err;
    }
}