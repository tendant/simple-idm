import { createSignal } from 'solid-js';
import { fetchWithAuth, useApiErrorHandler } from '../api';

interface UseApiOptions<T> {
  onSuccess?: (data: T) => void;
  onError?: (error: unknown) => void;
}

export function useApi<T>() {
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<Error | null>(null);
  const handleApiError = useApiErrorHandler();

  async function request<R = T>(
    url: string,
    options: RequestInit = {},
    apiOptions: UseApiOptions<R> = {}
  ): Promise<R | undefined> {
    setLoading(true);
    setError(null);

    try {
      const response = await fetchWithAuth(url, options);
      const data = await response.json();
      apiOptions.onSuccess?.(data);
      return data;
    } catch (err) {
      setError(err as Error);
      apiOptions.onError?.(err);
      handleApiError(err);
    } finally {
      setLoading(false);
    }
  }

  return {
    loading,
    error,
    request,
  };
}
