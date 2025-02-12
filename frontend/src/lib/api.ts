import { useNavigate } from '@solidjs/router';

// Singleton to track refresh token request
let refreshPromise: Promise<Response> | null = null;

interface ApiError extends Error {
  status?: number;
}

export async function refreshToken(): Promise<boolean> {
  try {
    const response = await fetch('/auth/refresh', {
      method: 'POST',
      credentials: 'include',
    });
    return response.ok;
  } catch (error) {
    return false;
  }
}

export async function fetchWithAuth(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  // First attempt
  let response = await fetch(url, {
    ...options,
    credentials: 'include', // Always send cookies
  });

  // If 401, try to refresh token
  if (response.status === 401) {
    // If there's already a refresh request in progress, wait for it
    if (refreshPromise) {
      await refreshPromise;
    } else {
      // Create new refresh request
      refreshPromise = fetch('/auth/refresh', {
        method: 'POST',
        credentials: 'include',
      });
      
      try {
        const refreshResponse = await refreshPromise;
        if (!refreshResponse.ok) {
          throw new Error('Token refresh failed');
        }
      } finally {
        refreshPromise = null;
      }
    }

    // Retry original request
    response = await fetch(url, {
      ...options,
      credentials: 'include',
    });
  }

  if (!response.ok) {
    const error: ApiError = new Error(response.statusText);
    error.status = response.status;
    throw error;
  }

  return response;
}

// Hook for handling API errors
export function useApiErrorHandler() {
  const navigate = useNavigate();

  return (error: unknown) => {
    if ((error as ApiError).status === 401) {
      // Redirect to login page
      navigate('/login', { replace: true });
    }
    // Handle other errors as needed
    throw error;
  };
}
