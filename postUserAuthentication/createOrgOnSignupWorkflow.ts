import {
  onPostAuthenticationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  createKindeAPI,
} from "@kinde/infrastructure";

// The settings for this workflow
export const workflowSettings: WorkflowSettings = {
  id: "postAuthentication",
  name: "CreateOrganizationOnSignUp",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.env": {},
    "kinde.fetch": {},
    "kinde.mfa": {},
    url: {},
  },
};

// This workflow requires you to set up the Kinde management API
// You can do this by going to the Kinde dashboard.
//
// Create an M2M application with the following scopes enabled:
// * create:organizations
// * update:organization_properties
// * read:businesses
//
// In Settings -> Environment variables set up the following variables with the
// values from the M2M application you created above:
//
// * KINDE_WF_M2M_CLIENT_ID
// * KINDE_WF_M2M_CLIENT_SECRET - Ensure this is setup with sensitive flag
// enabled to prevent accidental sharing
//

// The workflow code to be executed when the event is triggered
export default async function createOrgOnSignUp(event: onPostAuthenticationEvent) {
  const isNewKindeUser = event.context.auth.isNewUserRecordCreated;

  // The user has been added to the Kinde user pool for the first time
  if (isNewKindeUser) {
    try {
      // Get a token for Kinde management API
      const kindeAPI = await createKindeAPI(event);

      // Get the business details in order to set the organization name using the business name.
      const { data } = await kindeAPI.get({
        endpoint: "business",
      });
      
      // Call Kinde Organization API to create a new organization
      const { data: orgResponse } = await kindeAPI.post({
        endpoint: `organization`,
        params: {
          name: data.business.name,
        },
      });

      // Assuming company_head_count already exists. Update company head count property.
      await kindeAPI.patch({
        endpoint: `organizations/${orgResponse.organization.code}/properties`,
        params: {
          properties: {
            company_head_count: 50
          }
        }
      });
    } catch (error) {
      // Handle or log the error as needed
      console.error("Error creating organization on sign up:", error);
      // Optionally, rethrow or handle according to workflow requirements
      // throw error;
    }
  }
}
