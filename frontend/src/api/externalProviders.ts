// External Provider API client for simple-idm frontend

export interface ExternalProvider {
  id: string;
  name: string;
  display_name: string;
  enabled: boolean;
  icon_url?: string;
  description?: string;
}

export interface ProvidersResponse {
  providers: ExternalProvider[];
}

/**
 * Fetch available external providers
 */
export async function getExternalProviders(): Promise<ExternalProvider[]> {
  try {
    const response = await fetch('/api/idm/external/providers', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch providers: ${response.statusText}`);
    }

    const data: ProvidersResponse = await response.json();
    return data.providers || [];
  } catch (error) {
    console.error('Error fetching external providers:', error);
    throw error;
  }
}

/**
 * Initiate OAuth2 flow with an external provider
 * This will redirect the user to the provider's authorization page
 */
export function initiateOAuth2Flow(providerId: string, redirectUrl?: string): void {
  const params = new URLSearchParams();
  if (redirectUrl) {
    params.append('redirect_url', redirectUrl);
  }
  
  const url = `/api/idm/external/${providerId}${params.toString() ? '?' + params.toString() : ''}`;
  window.location.href = url;
}

/**
 * Check if the current URL contains OAuth2 callback parameters
 */
export function isOAuth2Callback(): boolean {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.has('auth') && urlParams.get('auth') === 'success';
}

/**
 * Check if the current URL contains OAuth2 error parameters
 */
export function hasOAuth2Error(): { error: string; description?: string } | null {
  const urlParams = new URLSearchParams(window.location.search);
  const error = urlParams.get('error');
  
  if (error) {
    return {
      error,
      description: urlParams.get('error_description') || undefined,
    };
  }
  
  return null;
}

/**
 * Clear OAuth2 parameters from the URL
 */
export function clearOAuth2Params(): void {
  const url = new URL(window.location.href);
  url.searchParams.delete('auth');
  url.searchParams.delete('error');
  url.searchParams.delete('error_description');
  
  // Update the URL without reloading the page
  window.history.replaceState({}, document.title, url.toString());
}

/**
 * Handle OAuth2 callback and show appropriate message
 */
export function handleOAuth2Callback(): { success: boolean; message: string } {
  if (isOAuth2Callback()) {
    clearOAuth2Params();
    return {
      success: true,
      message: 'Successfully authenticated! You are now logged in.',
    };
  }
  
  const error = hasOAuth2Error();
  if (error) {
    clearOAuth2Params();
    return {
      success: false,
      message: error.description || `Authentication failed: ${error.error}`,
    };
  }
  
  return {
    success: false,
    message: 'No authentication callback detected.',
  };
}
