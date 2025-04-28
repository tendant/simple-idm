/**
 * Utility function for making authenticated fetch requests
 */
export async function fetchWithAuth(url: string, options: RequestInit = {}) {
  // Add credentials to include cookies in the request
  const fetchOptions: RequestInit = {
    ...options,
    credentials: 'include',
    headers: {
      ...(options.headers || {}),
      'Content-Type': 'application/json',
    },
  };

  const response = await fetch(url, fetchOptions);
  
  // Handle 401 Unauthorized - redirect to login
  if (response.status === 401) {
    window.location.href = '/login';
    throw new Error('Authentication required');
  }
  
  return response;
}
