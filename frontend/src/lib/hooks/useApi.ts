import { createSignal } from 'solid-js';

import { fetchWithAuth, useApiErrorHandler } from '../api';

interface UseApiOptions<T> {
  onSuccess?: (data: T) => void
  onError?: (error: unknown) => void
}

export function useApi<T>() {
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<Error | null>(null);
  const handleApiError = useApiErrorHandler();

  async function request<R = T>(
    url: string,
    options: RequestInit = {},
    apiOptions: UseApiOptions<R> = {},
  ): Promise<R | undefined> {
    setLoading(true);
    setError(null);

    try {
      const response = await fetchWithAuth(url, options);

      // Check if the response is successful
      if (!response.ok) {
        // Try to parse the error response
        const errorData = await response.json().catch(() => null);

        // Create a custom error with additional properties from the response
        const error = new Error(errorData?.message || 'Request failed') as Error & {
          status?: number
          code?: string
          data?: any
        };

        // Add additional properties to the error
        error.status = response.status;
        error.code = errorData?.code;
        error.data = errorData;

        throw error;
      }

      const data = await response.json();
      apiOptions.onSuccess?.(data);
      return data;
    }
    catch (err) {
      setError(err as Error);
      apiOptions.onError?.(err);
      handleApiError(err);
    }
    finally {
      setLoading(false);
    }
  }

  return {
    loading,
    error,
    request,
  };
}
