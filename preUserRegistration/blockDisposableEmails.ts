import {
  onUserPreRegistrationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  denyAccess,
  getEnvironmentVariable,
} from "@kinde/infrastructure";

// The settings for this workflow
export const workflowSettings: WorkflowSettings = {
  id: "preRegistration",
  name: "Block disposable emails",
  failurePolicy: {
    action: "stop",
  },
  trigger: "user:pre_registration",
  bindings: {
    "kinde.env": {},
    "kinde.auth": {},
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
export default async function Workflow(
  event: onUserPreRegistrationEvent
) {
  console.log("handlePreRegistration", event);

  // Check if user email exists in the event
  if (!event.context.user.email) {
    console.log(
      "No user email found in pre-registration event, allowing registration"
    );
    return;
  }

  const disposableEmailDomains = getEnvironmentVariable(
    "DISPOSABLE_EMAIL_DOMAINS"
  )?.value;

  // If no disposable email domains are configured, allow registration
  if (!disposableEmailDomains) {
    console.log(
      "No disposable email domains configured, allowing registration"
    );
    return;
  }

  const disposableEmailDomainsArray = disposableEmailDomains
    .split(",")
    .map((domain) => domain.trim());

  const userEmailDomain = event.context.user.email.split("@")[1];

  if (disposableEmailDomainsArray.includes(userEmailDomain)) {
    console.log(
      `Blocking registration for disposable email domain: ${userEmailDomain}`
    );
    denyAccess("Disposable email domain detected");
  } else {
    console.log(`Allowing registration for email domain: ${userEmailDomain}`);
  }
}
