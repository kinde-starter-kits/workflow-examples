import { 
    createKindeAPI, 
    WorkflowSettings, 
    WorkflowTrigger,
} from "@kinde/infrastructure";


export const workflowSettings: WorkflowSettings = {
    id: "onTokenGeneration",
    name: "AddBillingDetailsToTokensB2C",
    trigger: WorkflowTrigger.UserTokenGeneration,
    failurePolicy: {
        action: "stop"
    },
    bindings: {
        "kinde.accessToken": {},
        "kinde.idToken": {},
        "kinde.env": {}, 
        url: {} // Enables URLSearchParams in the workflow environment
    }
};


// Types
interface WorkflowEvent {
    context: {
        user: {
            id: string;
        };
    };
    request?: unknown;
}

interface UserBilling {
    customer_id: string | null;
    [key: string]: unknown;
}

interface UserResponse {
    id?: string;
    name?: string;
    active?: boolean;
    [k: string]: unknown;
}

interface Entitlement {
    id?: string; 
    name?: string;
    active?: boolean;
    [k: string]: unknown;
}

interface EntitlementsResponse {
    entitlements?: Entitlement[];
    [k: string]: unknown;
}


interface Agreement {
    id?: string;
    [k: string]: unknown;
}

interface AgreementsResponse{
    agreements?: Agreement[];
    [k: string]: unknown;
}

interface BillingClaim {
    customer_id: string | null;
    user_billing: UserBilling;
    entitlements: Entitlement[];
    agreements: Agreement[];
}

// Helpers 
const ensureArray = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as  T[]) : []);


/**
 * Token generation workflow to add custom billing details claim to both the access token
 * and ID token. It first retrieves the data with the Kinde API and then constructs a claim object
 * and sets it as a custom claim in both tokens. 
 * 
 * Requirements:
 * 
 * 1. Create an M2M application in Kinde with the necessary billing API scopes:
 *      - read:users - for fetching user details including billing information 1
 *      - read:billing_entitlements - for accessing billing entitlements data
 *      - read:billing_agreements - for accessing billing agreements data
 * 
 *     Docs: https://docs.kinde.com/developer-tools/kinde-api/about-m2m-scopes/
 * 
 * 2. Add the M2M application's client ID and secret to the Kinde environment variables:
 *      - KINDE_M2M_CLIENT_ID
 *      - KINDE_M2M_CLIENT_SECRET (mark as sensitive)
 * 
 *      Docs: https://docs.kinde.com/build/env-variables/store-environment-variables/
 * 
 * 3. Ensure that the user has an associated customer ID in their billing details.
 * 
 * 
 * Once configured, this workflow will automatically add the billingDetails claim to tokens upon generation,
 * that is, after client authentication.
 * 
 * 
 * @param event - The event object containing the context and bindings
 * @returns <void> - This function does not return a value, but the custom claims are set in the tokens 
 */
export default async function Workflow(event) {
    try{
        console.log("Token generation workflow with custom code executed");

        const kindeAPI = await createKindeAPI(event);

        // [1] Get the relevant details to contruct the user billing claim object
        const userId = event.context?.user?.id;
        if(!userId){
            console.warn("No user id found in event.context.user.id — aborting workflow.");
            return;
        }

        const { data: user } = await kindeAPI.get<UserResponse>({
            endpoint: `user?id=${userId}&expand=billing`,
        });

        const customerId = user?.billing?.customer_id ?? null;
        if (!customerId) {
            console.info("No customer ID found for user, skipping billing claim construction.");
            return;
        }

        // Entitlements and Agreements
        const [entResp, agrResp] = await Promise.all([
            kindeAPI.get<EntitlementsResponse>({
            endpoint: `billing/entitlements?customer_id=${customerId}`
        }),
            kindeAPI.get<AgreementsResponse>({
            endpoint: `billing/agreements?customer_id=${customerId}`
        }),
        ]);

        const entitlements = ensureArray<Entitlement>(entResp?.data?.entitlements);
        const agreements = ensureArray<Agreement>(agrResp?.data?.agreements);


        // [2] Construct the user billing claim object 
        const billingClaimObject: BillingClaim = {
            customer_id: customerId,
            user_billing: user?.billing ?? {},
            entitlements,
            agreements
        };

        // [3] Set the billing claim object in both the access token and ID token
        kinde.accessToken.setCustomClaim("billingDetails", billingClaimObject);
        kinde.idToken.setCustomClaim("billingDetails", billingClaimObject);

        console.log(`billingDetails claim set on accessToken and idToken for user ${userId}`);


}
 catch (err){
        console.error("Workflow error:", (err as Error).message ?? err);

        throw err;
 }
}