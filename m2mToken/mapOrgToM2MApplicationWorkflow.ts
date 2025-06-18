import {
  onM2MTokenGeneratedEvent,
  WorkflowSettings,
  WorkflowTrigger,
  createKindeAPI,
  m2mTokenClaims
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
  id: "m2mTokenGeneration",
  name: "M2M custom claims",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.M2MTokenGeneration,
  bindings: {
    "kinde.m2mToken": {}, // required to modify M2M access token
    "kinde.fetch": {}, // Required for API calls
    "kinde.env": {}, // required to access your environment variables
    url: {}, // required for url params
  },
};

// This workflow requires you to set up the Kinde management API
// You can do this by going to the Kinde dashboard.
//
// Create an M2M application with the following scopes enabled:
// * read:application_properties
// * read:organizations
// * read:applications
//
// In Settings -> Environment variables set up the following variables with the
// values from the M2M application you created above:
//
// * KINDE_WF_M2M_CLIENT_ID
// * KINDE_WF_M2M_CLIENT_SECRET - Ensure this is setup with sensitive flag
// enabled to prevent accidental sharing
//
// Add a property to your M2M application with the key `org_code` and the value
// of the org code you want to use for the M2M token. This will be used to
// correlate the M2M token with the org data.

export default async function Workflow(event: onM2MTokenGeneratedEvent) {
  // Get a token for Kinde management API
  const kindeAPI = await createKindeAPI(event);

  const { clientId } = event.context.application;

  // Call Kinde applications properties API
  const { data } = await kindeAPI.get({
    endpoint: `applications/${clientId}/properties`,
  });
  const { appProperties } = data;

  // Get the org code property to make the correlation
  const orgCode = appProperties.find((prop) => prop.key === "org_code");

  // Get org data from Kinde management API
  const { data: org } = await kindeAPI.get({
    endpoint: `organization?code=${orgCode.value}`,
  });

  // set up types for the custom claims
  const m2mToken = m2mTokenClaims<{
    applicationId: string;
    orgName: string;
    orgCode: string;
  }>();

  // Use the data to set the org data on the M2M token
  m2mToken.applicationId = clientId;
  m2mToken.orgName = org.name;
  m2mToken.orgCode = org.code;
}
