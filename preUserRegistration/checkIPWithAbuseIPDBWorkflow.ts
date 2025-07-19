/**
 * AbuseIPDB IP Check Workflow
 * 
 * This workflow checks IP addresses against AbuseIPDB for abuse confidence scores.
 * It implements caching to improve performance and reduce API calls.
 * 
 * Environment Variables Required:
 * - ABUSEIPDB_API_KEY: Your AbuseIPDB API key (sensitive)
 * - ABUSEIPDB_BLOCK_THRESHOLD: A number from 0-100 (0 for very low risk, 100 for guaranteed high risk)
 * - ABUSEIPDB_TEST_FALSE_POSITIVE: Set to "TRUE" to test with a known bad IP (e.g., "64.227.0.197")
 * - ABUSEIPDB_CACHE_EXPIRY_SECONDS: How long to cache the AbuseIPDB results in seconds
 * - ABUSEIPDB_CACHE_URL: The URL for your caching service (e.g., Upstash Redis REST URL)
 * - ABUSEIPDB_CACHE_TOKEN_READ: The read token for your caching service (sensitive)
 * - ABUSEIPDB_CACHE_TOKEN_WRITE: The write token for your caching service (sensitive)
 * - ABUSEIPDB_FAIL_OPEN: Set to "TRUE" to allow access when API is unavailable (default: FALSE - blocks access)
 */

import {
  onPostAuthenticationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  getEnvironmentVariable,
  fetch,
  denyAccess,
} from '@kinde/infrastructure';

// --- Interfaces for API Responses ---

// Core data structure from AbuseIPDB API
interface AbuseIpdbCoreData {
  ipAddress: string;
  isPublic: boolean;
  abuseConfidenceScore: number;
  countryCode: string;
  isp: string;
  domain: string;
  isTor: boolean;
  totalReports: number;
  lastReportedAt: string | null;
}

// Structure of the raw AbuseIPDB API response
interface AbuseIpdbApiRawResponse {
  data: AbuseIpdbCoreData; // This 'data' property holds the core IP details
}

// Wrapper for Kinde's fetch response, if it directly contains the AbuseIPDB data
interface KindeFetchResponseWrapper {
  data: AbuseIpdbApiRawResponse;
}

// Error response structure from AbuseIPDB API
interface AbuseIpdbErrorResponse {
  errors: Array<{
    detail?: string;
    message?: string;
    status?: number;
  }>;
}

// --- Workflow Settings ---

export const workflowSettings: WorkflowSettings = {
  id: 'onPostUserAuthentication',
  name: 'Check for abuse confidence score from AbuseIPDB and cache results',
  failurePolicy: { action: 'stop' },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    'kinde.auth': {},
    'kinde.env': {},
    'kinde.fetch': {},
    'url': {},
  },
};

// --- Helper Functions ---

/**
 * Safely retrieves an environment variable.
 * @param varName The name of the environment variable.
 * @returns The value of the environment variable, or null if not found.
 */
function getEnvVar(varName: string): string | null {
  const envVar = getEnvironmentVariable(varName);
  if (!envVar?.value) {
    console.error(`Configuration error: Missing environment variable "${varName}".`);
    return null;
  }
  return envVar.value;
}

/**
 * Handles API errors by logging and denying access.
 * @param errorMessage The message to log and display to the user.
 * @param error The original error object (optional).
 */
function handleApiError(errorMessage: string, error?: any): void {
  console.error(`AbuseIPDB Workflow Error: ${errorMessage}`, error);
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

/**
 * Validates all required configuration values.
 * @returns Object with validated configuration or throws error.
 */
function validateConfiguration() {
  const config = {
    cacheURL: getEnvVar('ABUSEIPDB_CACHE_URL'),
    cacheTokenWrite: getEnvVar('ABUSEIPDB_CACHE_TOKEN_WRITE'),
    cacheTokenRead: getEnvVar('ABUSEIPDB_CACHE_TOKEN_READ'),
    cacheExpirySecondsStr: getEnvVar('ABUSEIPDB_CACHE_EXPIRY_SECONDS'),
    apiKey: getEnvVar('ABUSEIPDB_API_KEY'),
    blockThresholdStr: getEnvVar('ABUSEIPDB_BLOCK_THRESHOLD'),
  };

  const missingVars = Object.entries(config)
    .filter(([_, value]) => !value)
    .map(([key, _]) => key);

  if (missingVars.length > 0) {
    throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
  }

  const cacheExpirySeconds = parseInt(config.cacheExpirySecondsStr!, 10);
  if (isNaN(cacheExpirySeconds) || cacheExpirySeconds <= 0) {
    throw new Error('Invalid ABUSEIPDB_CACHE_EXPIRY_SECONDS. Must be a positive number.');
  }

  const blockThreshold = parseInt(config.blockThresholdStr!, 10);
  if (isNaN(blockThreshold) || blockThreshold < 0 || blockThreshold > 100) {
    throw new Error('Invalid ABUSEIPDB_BLOCK_THRESHOLD. Must be a number between 0 and 100.');
  }

  // Validate API key format (AbuseIPDB keys are typically 64 characters)
  if (!config.apiKey || config.apiKey.length < 10) {
    throw new Error('Invalid ABUSEIPDB_API_KEY. API key appears to be too short or missing.');
  }

  // Check for fail-open configuration
  const failOpen = getEnvVar('ABUSEIPDB_FAIL_OPEN') === 'TRUE';

  return {
    cacheURL: config.cacheURL!,
    cacheTokenWrite: config.cacheTokenWrite!,
    cacheTokenRead: config.cacheTokenRead!,
    apiKey: config.apiKey!,
    cacheExpirySeconds,
    blockThreshold,
    failOpen,
  };
}

/**
 * Attempts to retrieve an abuse confidence score from the cache.
 * @param cacheKey The unique key for the IP in the cache.
 * @param cacheURL The URL for the caching service.
 * @param cacheTokenRead The read token for the caching service.
 * @returns The cached abuse confidence score (0-100) if found and valid, otherwise undefined.
 */
async function getAbuseConfidenceScoreFromCache(
  cacheKey: string,
  cacheURL: string,
  cacheTokenRead: string
): Promise<number | undefined> {
  try {
    const getCacheResponse = await fetch(`${cacheURL}/get/${cacheKey}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${cacheTokenRead}`,
      },
    });

    const cachedScore = (getCacheResponse as any)?.data?.result;

    if (typeof cachedScore === 'string' && !isNaN(parseInt(cachedScore, 10))) {
      const parsedCachedScore = parseInt(cachedScore, 10);
      if (parsedCachedScore >= 0 && parsedCachedScore <= 100) {
        console.log(`IP found in cache. Using cached abuse confidence score: ${parsedCachedScore}`);
        return parsedCachedScore;
      }
    }
  } catch (error) {
    // Do not rethrow, allow workflow to proceed to API call if cache fails
  }
  console.log('IP not found in cache');
  return undefined;
}

/**
 * Attempts to store an abuse confidence score in the cache.
 * @param cacheKey The unique key for the IP in the cache.
 * @param score The abuse confidence score to cache.
 * @param cacheExpirySeconds The expiry time for the cache entry in seconds.
 * @param cacheURL The URL for the caching service.
 * @param cacheTokenWrite The write token for the caching service.
 */
async function setAbuseConfidenceScoreInCache(
  cacheKey: string,
  score: number,
  cacheExpirySeconds: number,
  cacheURL: string,
  cacheTokenWrite: string
): Promise<void> {
  try {
    const setUrl = `${cacheURL}/set/${cacheKey}?EX=${cacheExpirySeconds}`;
    await fetch(setUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${cacheTokenWrite}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(score),
    });
    console.log(`Cached abuse confidence score: ${score}`);
  } catch (cacheError) {
    // Do not deny access if caching fails, the core check was successful
  }
}

// --- Main Workflow Handler ---

export default async function handlePostAuth(
  event: onPostAuthenticationEvent
) {
  console.log('AbuseIPDB workflow started.');

  // 1. Retrieve and Validate Environment Variables
  let config;
  try {
    config = validateConfiguration();
  } catch (error) {
    return handleApiError(`Configuration error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  // Determine the IP address to check
  let ip = event.request.ip?.split(',')[0].trim() ?? 'unknown';
  const testFalsePositive = getEnvVar('ABUSEIPDB_TEST_FALSE_POSITIVE');

  if (testFalsePositive === 'TRUE') {
    ip = '64.227.0.197'; // A known "bad" IP for testing purposes
    console.log('ABUSEIPDB_TEST_FALSE_POSITIVE is TRUE. Using a known bad IP for testing.');
  }

  // Validate IP address
  if (!isValidIpAddress(ip)) {
    console.warn(`Invalid or private IP address detected: ${ip}. Skipping AbuseIPDB check.`);
    console.log('IP check completed successfully. Access granted.');
    return;
  }

  let abuseConfidenceScore: number | undefined;
  const cacheKey = `abuseipdb:ip:${ip}`;

  // 2. Check Cache using the new function
  console.log('Checking cache for IP...');
  abuseConfidenceScore = await getAbuseConfidenceScoreFromCache(
    cacheKey,
    config.cacheURL,
    config.cacheTokenRead
  );

  // 3. Fetch from AbuseIPDB if not in cache
  if (typeof abuseConfidenceScore === 'undefined') {
    console.log('IP not in cache. Fetching from AbuseIPDB...');
    try {
      const response = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose=true`,
        {
          method: 'GET',
          headers: {
            'Key': config.apiKey,
            'Accept': 'application/json',
          },
        }
      );

      let fetchedData: any;

      // Parse response
      if ('json' in response && typeof response.json === 'function') {
        fetchedData = await (response as any).json();
      } else if ('data' in response) {
        fetchedData = (response as any).data;
      } else {
        fetchedData = response;
      }

      // Handle server errors gracefully
      if (fetchedData && fetchedData.message === 'Server Error') {
        if (config.failOpen) {
          console.warn('AbuseIPDB API server error. Fail-open mode enabled - allowing access.');
          abuseConfidenceScore = 0;
        } else {
          throw new Error('AbuseIPDB API server error. Access blocked.');
        }
      } else if (fetchedData && fetchedData.errors && fetchedData.errors.length > 0) {
        const apiErrors = fetchedData.errors.map((err: any) => err.detail || err.message).join(', ');
        if (config.failOpen) {
          console.warn(`AbuseIPDB API errors: ${apiErrors}. Fail-open mode enabled - allowing access.`);
          abuseConfidenceScore = 0;
        } else {
          throw new Error(`AbuseIPDB API errors: ${apiErrors}`);
        }
      } else if (response.status && response.status >= 400) {
        if (config.failOpen) {
          console.warn(`AbuseIPDB API HTTP ${response.status}. Fail-open mode enabled - allowing access.`);
          abuseConfidenceScore = 0;
        } else {
          throw new Error(`AbuseIPDB API HTTP ${response.status}`);
        }
      } else {
        // Try to extract abuse confidence score
        let abuseScore: number | undefined;

        if (fetchedData?.data?.data?.abuseConfidenceScore !== undefined) {
          abuseScore = fetchedData.data.data.abuseConfidenceScore;
        } else if (fetchedData?.data?.abuseConfidenceScore !== undefined) {
          abuseScore = fetchedData.data.abuseConfidenceScore;
        } else if (fetchedData?.abuseConfidenceScore !== undefined) {
          abuseScore = fetchedData.abuseConfidenceScore;
        }

        if (typeof abuseScore === 'number' && abuseScore >= 0 && abuseScore <= 100) {
          abuseConfidenceScore = abuseScore;

          // Cache the result
          await setAbuseConfidenceScoreInCache(
            cacheKey,
            abuseConfidenceScore,
            config.cacheExpirySeconds,
            config.cacheURL,
            config.cacheTokenWrite
          );
        } else if (response.status >= 200 && response.status < 300) {
          if (config.failOpen) {
            console.warn('Could not parse AbuseIPDB response. Fail-open mode enabled - allowing access.');
            abuseConfidenceScore = 0;
          } else {
            throw new Error('AbuseIPDB API response missing valid abuseConfidenceScore.');
          }
        } else {
          if (config.failOpen) {
            console.warn('AbuseIPDB API response missing valid abuseConfidenceScore. Fail-open mode enabled - allowing access.');
            abuseConfidenceScore = 0;
          } else {
            throw new Error('AbuseIPDB API response missing valid abuseConfidenceScore.');
          }
        }
      }
    } catch (error) {
      if (config.failOpen) {
        console.warn(`Failed to fetch AbuseIPDB data: ${error instanceof Error ? error.message : 'Unknown error'}. Fail-open mode enabled - allowing access.`);
        abuseConfidenceScore = 0;
      } else {
        return handleApiError(`Failed to fetch AbuseIPDB data: ${error instanceof Error ? error.message : 'Unknown error'}`, error);
      }
    }
  }

  // 4. Evaluate Score and Deny/Grant Access
  if (typeof abuseConfidenceScore === 'undefined') {
    if (config.failOpen) {
      console.warn('AbuseIPDB confidence score could not be determined after all attempts. Allowing access due to fail-open configuration.');
      console.log('IP check completed with warning. Access granted.');
      return;
    } else {
      return handleApiError('AbuseIPDB confidence score could not be determined after all attempts. Access blocked.', null);
    }
  }

  console.log(`Final AbuseIPDB confidence score: ${abuseConfidenceScore}`);
  console.log(`Configured block threshold: ${config.blockThreshold}`);

  if (abuseConfidenceScore > config.blockThreshold) {
    console.warn(`Blocking access due to high abuse confidence score (${abuseConfidenceScore}).`);
    denyAccess('Malicious IP detected. Access blocked.');
    return;
  }

  console.log('IP check completed successfully. Access granted.');
}