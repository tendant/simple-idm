/**
 * Utility functions for the API
 */

/**
 * Generates a random string of the specified length
 * @param length The length of the random string to generate
 * @returns A random string
 */
export function GenerateRandomString(length: number): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  
  return result;
}

/**
 * Formats a date string to a human-readable format
 * @param dateString The date string to format
 * @returns A formatted date string
 */
export function formatDate(dateString: string | undefined): string {
  if (!dateString) return 'N/A';
  
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

/**
 * Truncates a string to the specified length and adds an ellipsis if needed
 * @param str The string to truncate
 * @param maxLength The maximum length of the string
 * @returns The truncated string
 */
export function truncateString(str: string, maxLength: number): string {
  if (!str) return '';
  if (str.length <= maxLength) return str;
  
  return str.substring(0, maxLength) + '...';
}
