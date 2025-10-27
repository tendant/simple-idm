import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Checks if a URL is an absolute URL (has protocol like http:// or https://)
 */
export function isAbsoluteUrl(url: string): boolean {
  try {
    // Try to parse as URL - will throw if not absolute
    new URL(url);
    return true;
  } catch {
    // Not a valid absolute URL
    return false;
  }
}

/**
 * Checks if a URL points to the same origin as the current page
 */
export function isSameOrigin(url: string): boolean {
  try {
    const urlObj = new URL(url, window.location.origin);
    return urlObj.origin === window.location.origin;
  } catch {
    return false;
  }
}

/**
 * Determines if a redirect needs a full page reload (window.location.href)
 * vs client-side routing (navigate)
 *
 * Returns true if:
 * - URL is absolute and points to a different origin
 * - URL is absolute and same origin but different port (different service)
 * - URL contains backend API paths that require full page reload (OAuth2 authorization flows)
 *
 * Returns false for:
 * - Relative URLs (internal frontend routes)
 * - Same origin + same port URLs that are frontend routes
 */
export function needsFullRedirect(url: string): boolean {
  // Relative URLs always use client-side routing
  if (!isAbsoluteUrl(url)) {
    return false;
  }

  // It's an absolute URL - parse it
  try {
    const urlObj = new URL(url);
    const currentOrigin = new URL(window.location.href);

    // Different origin (different domain or protocol) - needs full redirect
    if (urlObj.origin !== currentOrigin.origin) {
      return true;
    }

    // Same origin - check if it's a backend endpoint that needs full page handling
    // These patterns indicate backend OAuth2/OIDC flows that must not use client routing:
    // - /oauth2/authorize - OAuth2 authorization endpoint (user-facing)
    // - /api/oauth2/* - OAuth2 API endpoints (token, userinfo, jwks)
    // - Any URL with OAuth2-related query parameters
    const pathname = urlObj.pathname;
    const searchParams = urlObj.searchParams;

    // Check for OAuth2 authorization flow (has client_id, redirect_uri, response_type)
    const isOAuth2Flow = searchParams.has('client_id') &&
                         searchParams.has('redirect_uri') &&
                         searchParams.has('response_type');

    // Check for backend OAuth2/OIDC endpoints
    const isBackendOAuth2Path = pathname.startsWith('/oauth2/') ||
                                pathname.startsWith('/api/oauth2/') ||
                                pathname.includes('/oauth2/authorize') ||
                                pathname.includes('/oauth2/token');

    if (isOAuth2Flow || isBackendOAuth2Path) {
      return true;
    }

    // Same origin, not an OAuth2 endpoint - can use client-side routing
    return false;
  } catch {
    // If URL parsing fails, default to full redirect for safety
    return true;
  }
}
