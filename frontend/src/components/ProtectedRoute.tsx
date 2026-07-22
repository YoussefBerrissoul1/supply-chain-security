import React, { lazy, Suspense } from 'react';

// Lazy load the status pages for security redirects
const Page401 = lazy(() => import('@/pages/status/Page401'));
const Page403 = lazy(() => import('@/pages/status/Page403'));

interface ProtectedRouteProps {
  component: React.ComponentType<any>;
  requiredRoles?: string[];
  [key: string]: any;
}

/**
 * A wrapper component for securing wouter routes.
 * It checks authentication and authorization (roles).
 */
export function ProtectedRoute({ component: Component, requiredRoles, ...rest }: ProtectedRouteProps) {
  // MOCK AUTHENTICATION LOGIC
  // TODO: Replace with real authentication context hook (e.g., const { isAuthenticated, role } = useAuth();)
  const isAuthenticated = true; // Set to true to allow access for now, set to false to see 401
  const userRole = 'USER';      // e.g., 'ADMIN', 'USER'

  if (!isAuthenticated) {
    // Return 401 Unauthorized securely without changing the URL immediately
    return (
      <Suspense fallback={null}>
        <Page401 />
      </Suspense>
    );
  }

  if (requiredRoles && !requiredRoles.includes(userRole)) {
    // Return 403 Forbidden securely
    return (
      <Suspense fallback={null}>
        <Page403 />
      </Suspense>
    );
  }

  return <Component {...rest} />;
}
