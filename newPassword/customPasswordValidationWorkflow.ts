import {
  onNewPasswordProvidedEvent,
  WorkflowSettings,
  WorkflowTrigger,
  invalidateFormField,
} from "@kinde/infrastructure";

// The setting for this workflow
export const workflowSettings: WorkflowSettings = {
  id: "onNewPasswordProvided",
  trigger: WorkflowTrigger.NewPasswordProvided,
  failurePolicy: {
    action: "stop",
  },
  bindings: {
    "kinde.widget": {}, // Required for accessing the UI
  },
};

// The workflow code to be executed when the event is triggered
export default async function Workflow(event: onNewPasswordProvidedEvent) {
  const isMinCharacters = event.context.auth.firstPassword.length >= 50;

  if (!isMinCharacters) {
    // Custom form validation
    invalidateFormField(
      "p_first_password",
      "Your password must be at least 50 characters long"
    );
  }
}
