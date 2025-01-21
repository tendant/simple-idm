interface RequestConfig extends RequestInit {
  skipAuth?: boolean;
}

let refreshPromise: Promise<void> | null = null;

// Function to redirect to login page
function redirectToLogin() {
  // Clear any auth-related data from localStorage
  localStorage.removeItem('user');
  
  // Get the current path to redirect back after login
  const currentPath = window.location.pathname;
  const loginPath = `/login${currentPath !== '/login' ? `?redirect=${encodeURIComponent(currentPath)}` : ''}`;
  
  // Use replace to prevent back button from returning to the failed page
  window.location.replace(loginPath);
}

async function refreshToken() {
  if (refreshPromise) {
    return refreshPromise;
  }

  refreshPromise = fetch('/auth/token/refresh', {
    method: 'POST',
    credentials: 'include',
  }).then(async (response) => {
    if (!response.ok) {
      if (response.status === 401) {
        redirectToLogin();
      }
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
  // Skip auth for login-related endpoints
  if (config.skipAuth) {
    return fetch(url, {
      ...config,
      credentials: 'include',
    });
  }

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
    // If refresh token fails, redirect to login
    redirectToLogin();
    throw error;
  }
}
