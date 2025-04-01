// Clear all auth-related data from localStorage
function clearAuthData() {
  localStorage.removeItem('user');
  // Add any other auth-related items to clear here
}

export async function logout() {
  try {
    const response = await fetch('/api/idm/auth/logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error('Failed to logout');
    }

    // Clear auth data and redirect to login page
    clearAuthData();
    window.location.href = '/login';
  }
  catch (error) {
    console.error('Logout failed:', error);
    throw error;
  }
}
