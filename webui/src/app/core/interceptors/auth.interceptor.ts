/**
 * Authentication HTTP Interceptor
 *
 * Automatically adds JWT token to outgoing HTTP requests
 */

import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from '../services/auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const token = authService.getToken();

  // Don't add token to auth endpoints (they don't need it)
  if (req.url.includes('/auth/')) {
    return next(req);
  }

  // Add Authorization header if token exists
  if (token) {
    const cloned = req.clone({
      headers: req.headers.set('Authorization', `Bearer ${token}`),
    });
    return next(cloned);
  }

  return next(req);
};
