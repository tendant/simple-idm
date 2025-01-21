interface RequestConfig extends RequestInit {
  skipAuth?: boolean;
}

let refreshPromise: Promise<void> | null = null;

async function refreshToken() {
  if (refreshPromise) {
    return refreshPromise;
  }

  refreshPromise = fetch('/auth/token/refresh', {
    method: 'POST',
    credentials: 'include',
  }).then(async (response) => {
    if (!response.ok) {
      throw new Error('Failed to refresh token');
    }
    refreshPromise = null;
  }).catch((error) => {
    refreshPromise = null;
    throw error;
  });

  return refreshPromise;
}

export async function apiClient(url: string, config: RequestConfig = {}): Promise<Response> {
  // First attempt
  const response = await fetch(url, {
    ...config,
    credentials: 'include',
  });

  // If not 401, return the response
  if (response.status !== 401) {
    return response;
  }

  try {
    // Try to refresh the token
    await refreshToken();

    // Retry the original request
    const retryResponse = await fetch(url, {
      ...config,
      credentials: 'include',
    });

    return retryResponse;
  } catch (error) {
    // If refresh fails, throw an error that can be handled by the UI
    throw new Error('Authentication expired. Please log in again.');
  }
}
