import {
  onPostAuthenticationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  getEnvironmentVariable,
  createKindeAPI,
  fetch,
  denyAccess,
} from "@kinde/infrastructure";

// Workflow settings
export const workflowSettings: WorkflowSettings = {
  id: "impossibleTravelWorkflow",
  name: "ImpossibleTravelCheck (TrustPath)",
  failurePolicy: { action: "stop" },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.auth": {},
    "kinde.env": {},     // for env variables
    "kinde.fetch": {},   // for API requests
    "url": {},           // required
  },
};

// Workflow logic
export default async function handlePostAuth(
  event: onPostAuthenticationEvent
) {
  const userId = event.context.user.id;
  const isNew = event.context.auth.isNewUserRecordCreated;
  const ip = event.request.ip?.split(",")[0].trim() ?? "unknown";

  console.log("Workflow started", { userId, ip, isNewUser: isNew });

  // Initialize Kinde API
  const kindeAPI = await createKindeAPI(event);

  // Get user details
  const { data: user } = await kindeAPI.get({
    endpoint: `user?id=${userId}`,
  });

  console.log("Retrieved user from Kinde", {
    id: user.id,
    email: user.preferred_email,
  });

  // Build TrustPath payload
  const payload = {
    ip,
    email: user.preferred_email,
    user: {
      user_id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
    },
    event_type: isNew ? "account_register" : "account_login",
  };

  console.log("Payload prepared", payload);

  // Read TrustPath API key from env
  const apiKey = getEnvironmentVariable("TRUSTPATH_API_KEY")?.value;
  if (!apiKey) {
    console.error("TRUSTPATH_API_KEY is missing");
    throw new Error("Missing TrustPath API Key");
  }

  let state: string | undefined;

  try {
    const { data: trustData } = await fetch(
      "https://api.trustpath.io/v1/risk/evaluate",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: payload,
        responseFormat: "json",
      }
    );

    console.log("TrustPath response", trustData);

    state = trustData?.data?.score?.state;

    if (typeof state !== "string") {
      throw new Error("Invalid state format in TrustPath response");
    }
  } catch (error) {
    console.error("Error during TrustPath evaluation", error);
    denyAccess("Unable to evaluate login risk. Access blocked.");
    return;
  }

  console.log("Decision state:", state);

  if (state === "decline") {
    console.log("Declined — denying access");
    denyAccess("Access blocked due to impossible travel risk.");
  } else {
    console.log("Approved — allowing access");
  }
}