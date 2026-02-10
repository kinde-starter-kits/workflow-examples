import {
  onUserPreMFA,
  WorkflowSettings,
  WorkflowTrigger,
  setEnforcementPolicy,
  getEnvironmentVariable,
  MFAEnforcementPolicy,
  createKindeAPI,
} from "@kinde/infrastructure";

const MFAPolicy: {[key: string]: MFAEnforcementPolicy} = {
  Required: "required",
  Skip: "skip"
} as const;

// The setting for this workflow
export const workflowSettings: WorkflowSettings = {
  id: "onUserPreMFA",
  trigger: WorkflowTrigger.UserPreMFA,
  failurePolicy: {
    action: "stop",
  },
  bindings: {
    "kinde.fetch": {}, // Required for external API calls
    "kinde.env": {}, // required to access your environment variables
    "kinde.mfa": {}, // required to use setEnforcementPolicy
    url: {}, // required for url params
  },
};

// This workflow requires you to set up the Kinde management API
// You can do this by going to the Kinde dashboard.
//
// Create an M2M application with the following scopes enabled:
// * read:user_mfa
//
// In Settings -> Environment variables set up the following variables with the
// values from the M2M application you created above:
//
// * KINDE_WF_M2M_CLIENT_ID
// * KINDE_WF_M2M_CLIENT_SECRET - Ensure this is setup with sensitive flag
// enabled to prevent accidental sharing
//
// Add an environment variable with the key `MFA_GRACE_PERIOD_IN_HOURS`
// and the value of the grace period you want to use for MFA.
// This will be used to determine if the user has completed MFA within the
// grace period.

// The workflow code to be executed when the event is triggered
export default async function Workflow(event: onUserPreMFA) {
  const MFA_GRACE_PERIOD_IN_MS =
    Number(getEnvironmentVariable("MFA_GRACE_PERIOD_IN_HOURS")?.value) *
    60 *
    60 *
    1000;

  let MFA_POLICY: MFAEnforcementPolicy = MFAPolicy.Required;

  try {
    const {
      user: { id: userId },
    } = event.context;

    const kindeAPI = await createKindeAPI(event);

    const { data: response } = (await kindeAPI.get({
      endpoint: `users/${userId}/mfa`,
    })) || { data: null };

    if (response?.mfa) {
      // Find out when user last completed MFA
      const lastUsedDate = new Date(response.mfa.last_used_on);
      const lastUsedDateMS = lastUsedDate.getTime();

      const currentDate = new Date();
      const currentDateMS = currentDate.getTime();

      // Check if the last used date is within the grace period
      const isMfaUsedWithinGracePeriod =
        lastUsedDateMS + MFA_GRACE_PERIOD_IN_MS > currentDateMS;

      MFA_POLICY = isMfaUsedWithinGracePeriod
        ? MFAPolicy.Skip
        : MFAPolicy.Required;
    } else {
      MFA_POLICY = MFAPolicy.Required;
    }
  } catch (error) {
    MFA_POLICY = MFAPolicy.Required;
  }

  console.log("Setting MFA policy:", MFA_POLICY);
  setEnforcementPolicy(MFA_POLICY);
}
