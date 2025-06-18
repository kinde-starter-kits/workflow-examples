import {
  onUserPreRegistrationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  denyAccess,
  getEnvironmentVariable
} from "@kinde/infrastructure";

// The settings for this workflow
export const workflowSettings: WorkflowSettings = {
  id: "preRegistration",
  name: "Block disposable emails",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.UserPreRegistration,
  bindings: {
    "kinde.env": {},
  },
};

// This workflow allows you to block users from registering with disposable email domains.
//
// In Settings -> Environment variables set up the following variable with the
// * DISPOSABLE_EMAIL_DOMAINS - A comma separated list of disposable email domains
//
// For example, if you want to block users from registering with disposable email domains like
// @yopmail.com, @guerrillamail.com, @mailinator.com, you can set the variable to:
//
// yopmail.com,guerrillamail.com,mailinator.com
//
// You could also hardcode the disposable email domains in the workflow code, but this is not recommended
// as it makes it harder to manage and update the list of disposable email domains.

// The workflow code to be executed when the event is triggered
export default async function handlePreRegistration(event: onUserPreRegistrationEvent) {
  const disposableEmailDomains = getEnvironmentVariable("DISPOSABLE_EMAIL_DOMAINS")?.value;
  const disposableEmailDomainsArray = disposableEmailDomains?.split(",");

  if (disposableEmailDomainsArray?.includes(event.context.user.email.split("@")[1])) {
    denyAccess("Disposable email domain detected");
  }
}
