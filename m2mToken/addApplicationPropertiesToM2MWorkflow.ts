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
    "kinde.m2mToken": {},
    "kinde.fetch": {},
    "kinde.env": {},
    "kinde.mfa": {},
    url: {},
  },
};

// This workflow requires you to set up the Kinde management API
// You can do this by going to the Kinde dashboard.
//
// Create an M2M application with the following scopes enabled:
// * read:application_properties
// * read:applications
//
// In Settings -> Environment variables set up the following variables with the
// values from the M2M application you created above:
//
// * KINDE_WF_M2M_CLIENT_ID
// * KINDE_WF_M2M_CLIENT_SECRET - Ensure this is setup with sensitive flag
// enabled to prevent accidental sharing
//

export default async function Workflow(event: onM2MTokenGeneratedEvent) {
  const kindeAPI = await createKindeAPI(event);

  const { clientId } = event.context.application;

  const { data } = await kindeAPI.get({
    endpoint: `applications/${clientId}/properties`,
  });

  const { properties: appProperties } = data;

  // implement custom logic here to filter properties if needed.

  const m2mToken = m2mTokenClaims<{
    applicationProperties: any;
  }>();

  m2mToken.applicationProperties = appProperties;
}