/**
 * Allowlist IP Check Workflow
 *
 * This workflow runs after user authentication and enforces an IP allowlist.
 * It validates the configured allowlist, extracts the client's IP from the
 * authentication event, validates the IP format, and either grants or denies
 * access depending on whether the IP is present in the allowlist.
 *
 * Key behaviors:
 *  - Validates the allowlist is a non-empty array of valid IPv4 addresses.
 *  - Extracts the client's IP from `event.request.ip` (first value when CSV).
 *  - Supports a developer test mode to override the detected IP for testing.
 *  - Denies access when IP is missing/invalid or not present in the allowlist.
 *  - Logs warnings and errors; on unexpected exceptions denies access.
 *
 * Recommended updates:
 *  - allowList: Update the `allowList` array with the desired IP addresses to allow.
 *
 * Testing:
 *  - Enable ALLOWLIST_TEST_FALSE_POSITIVE (or set testFalsePositive = true)
 *    to force the workflow to use a known test IP for functional verification.
 *  - Use an authentication event with `request.ip` in CSV format (e.g.
 *    "203.0.113.5, 10.0.0.1") to verify the first IP segment is used.
 *
 * Failure & error handling:
 *  - Invalid allowlist or invalid IP -> denyAccess with descriptive message.
 *  - Unexpected exceptions -> logged to console and denyAccess invoked.
 *
 */



import {
  onPostAuthenticationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  denyAccess,
} from "@kinde/infrastructure";


// --- Configuration ---
const allowList = [
  '64.227.0.197',
]
const testFalsePositive = true; 


// --- Workflow Settings ---
export const workflowSettings: WorkflowSettings = {
  id: "onPostUserAuthentication",
  name: "checkIPAgainstAllowlist",
  failurePolicy: { action: 'stop' },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
  "kinde.auth": {},
  }
};

// --- Helper functions ---

/**
 * Safely retrieves the allowlist of IPs.
 * @param allowList: array of strings - The allowlist to validate.
 * @returns void if valid, otherwise throws an error.
 */
function validateAllowList(allowList: string[]): void {

  if (!Array.isArray(allowList) || allowList.length === 0) {
    throw new Error("Allowlist must be a non-empty array.");

  }
  for (const ip of allowList) {
    if (typeof ip !== 'string' || !isValidIpAddress(ip)) {
      throw new Error(`Invalid IP address in allowlist: ${ip}`);
    }
  }
}

/**
 * Handles general errors by logging and denying access.
 * @param errorMessage The message to log and display to the user.
 * @param error The original error object (optional).
 */
function handleExceptionError(errorMessage: string, error?: any): void {
  console.error(`Check Againts IP Address Workflow Error: ${errorMessage}`, error); 
  denyAccess(`Access blocked due to an issue: ${errorMessage}`);
}

/**
 * Validates if a string is a valid IP address.
 * @param ip The IP address to validate.
 * @returns True if valid, false otherwise.
 */
function isValidIpAddress(ip: string): boolean {
  if (ip === 'unknown' || ip === 'localhost' || ip === '127.0.0.1') {
    return false;
  }

  // Basic IPv4 validation
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
}


// --- Main Workflow Handler ---
export default async function handlePostAuth(event: onPostAuthenticationEvent) {
  console.log("Check IP Against Allowlist Workflow started");

  try {
    // 1. Retrieve and validate allowlist
    validateAllowList(allowList);

    // 2. Get and validate IP address
    let ip = event.request.ip?.split(',')[0].trim() ?? 'unknown';
    if (testFalsePositive) {
      ip = '64.227.0.197'; // A known "allowed" IP for testing purposes
      console.log('Test false positive is enabled. Overriding IP for testing purposes.');
    }

    // Validate IP address
    if (!isValidIpAddress(ip)) {
      console.warn(`Invalid or private IP address detected: ${ip}. Access denied.`);
      denyAccess(`Access denied: Invalid or private IP address.`);
      return;
    }

    console.log("Allowlist and IP address validation passed.");

    // 3. Deny or allow access 
    if (!allowList.includes(ip)) {
      console.warn(`IP address ${ip} is not in the allowlist. Access denied.`);
      denyAccess(`Access denied: IP address ${ip} is not in the allowlist.`);
      return;
    }

    console.log('IP check completed successfully. Access granted.');
  } 
  
  catch (error: any) {
    handleExceptionError(error.message, error);
  }

}
