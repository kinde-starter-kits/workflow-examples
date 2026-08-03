import {
  onUserTokenGeneratedEvent,
  WorkflowSettings,
  WorkflowTrigger,
  accessTokenCustomClaims,
  getEnvironmentVariable,
  fetch,
} from "@kinde/infrastructure";

// The setting for this workflow
export const workflowSettings: WorkflowSettings = {
  id: "onUserTokenGeneration",
  trigger: WorkflowTrigger.UserTokenGeneration,
  failurePolicy: {
    action: "stop",
  },
  bindings: {
    "kinde.accessToken": {}, // required to modify access token claims
    "kinde.fetch": {}, // Required for external API calls
    "kinde.env": {}, // required to access your environment variables
    url: {}, // required for url params
  },
};

// This workflow demonstrates calling an external API to get some data
// to add as a custom claim.
// It assumes API keys are used to access the API
// Add an environment variable with the key `MY_API_KEY`

// The workflow code to be executed when the event is triggered
export default async function Workflow(event: onUserTokenGeneratedEvent) {
  // Get the API key you set in Kinde as an environment variable
  const MY_API_KEY = getEnvironmentVariable("MY_API_KEY")?.value;

  const { data: crmData } = await fetch(
    `https://somecrm.io/?api_key=${MY_API_KEY}`,
    {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );

  // set the types for the custom claims
  const accessToken = accessTokenCustomClaims<{
    companyName: string;
  }>();

  // Add the users company name to the access token
  accessToken.companyName = crmData.companyName;
}
