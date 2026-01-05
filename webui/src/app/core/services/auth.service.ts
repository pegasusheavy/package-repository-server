/**
 * Authentication Service for SSO Integration
 *
 * Supports multiple SSO providers (Google, GitHub, GitLab, Microsoft, Azure, Okta, Auth0, etc.)
 * Handles JWT token management and user session state
 */

import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, BehaviorSubject, of, throwError } from 'rxjs';
import { tap, catchError, map } from 'rxjs/operators';

export interface SsoProvider {
  id: string;
  name: string;
  enabled: boolean;
}

export interface UserInfo {
  email: string;
  name?: string;
  email_verified: boolean;
  provider: string;
}

export interface LoginResponse {
  success: boolean;
  token: string;
  user: UserInfo;
  expires_at: number;
}

export interface AuthState {
  isAuthenticated: boolean;
  user: UserInfo | null;
  token: string | null;
  expiresAt: number | null;
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);

  private readonly API_BASE = '/api/v1'; // Adjust based on your API configuration
  private readonly AUTH_BASE = '/auth';
  private readonly TOKEN_KEY = 'auth_token';
  private readonly USER_KEY = 'user_info';
  private readonly EXPIRES_KEY = 'token_expires';

  // Reactive state using signals (Angular 21 feature)
  isAuthenticated = signal(false);
  currentUser = signal<UserInfo | null>(null);

  // Observable state for compatibility
  private authState$ = new BehaviorSubject<AuthState>({
    isAuthenticated: false,
    user: null,
    token: null,
    expiresAt: null,
  });

  constructor() {
    this.loadAuthStateFromStorage();
  }

  /**
   * Get list of available SSO providers
   */
  getProviders(): Observable<SsoProvider[]> {
    return this.http.get<{ providers: SsoProvider[] }>(`${this.AUTH_BASE}/providers`).pipe(
      map((response) => response.providers),
      catchError((error) => {
        console.error('Failed to fetch SSO providers:', error);
        return of([]);
      })
    );
  }

  /**
   * Initiate SSO login with a specific provider
   */
  loginWithProvider(providerId: string): void {
    this.http
      .get<{ authorization_url: string; state: string }>(`${this.AUTH_BASE}/login/${providerId}`)
      .subscribe({
        next: (response) => {
          // Backend is stateless - state is encrypted and validated server-side
          // No need to store anything client-side, just redirect
          window.location.href = response.authorization_url;
        },
        error: (error) => {
          console.error('Failed to initiate SSO login:', error);
          // Handle error (show notification, etc.)
        },
      });
  }

  /**
   * Handle OAuth callback
   * 
   * Backend is stateless - state validation happens server-side using
   * encrypted state parameter. No client-side validation needed.
   */
  handleCallback(providerId: string, code: string, state: string): Observable<boolean> {
    return this.http
      .get<LoginResponse>(`${this.AUTH_BASE}/callback/${providerId}`, {
        params: { code, state },
      })
      .pipe(
        tap((response) => {
          if (response.success) {
            this.setAuthState(response.token, response.user, response.expires_at);
          }
        }),
        map((response) => response.success),
        catchError((error) => {
          console.error('OAuth callback failed:', error);
          return throwError(() => error);
        })
      );
  }

  /**
   * Validate current session token
   */
  validateSession(): Observable<boolean> {
    const token = this.getToken();
    if (!token) {
      return of(false);
    }

    // Check if token is expired
    if (this.isTokenExpired()) {
      this.clearAuthState();
      return of(false);
    }

    return this.http
      .get<{ valid: boolean; user: UserInfo; expires_at: number }>(`${this.AUTH_BASE}/validate`)
      .pipe(
        tap((response) => {
          if (response.valid) {
            this.setUserInfo(response.user, response.expires_at);
          } else {
            this.clearAuthState();
          }
        }),
        map((response) => response.valid),
        catchError(() => {
          this.clearAuthState();
          return of(false);
        })
      );
  }

  /**
   * Logout current user
   */
  logout(): void {
    this.http
      .post(`${this.AUTH_BASE}/logout`, {})
      .pipe(
        catchError((error) => {
          console.error('Logout failed:', error);
          return of(null);
        })
      )
      .subscribe(() => {
        this.clearAuthState();
        this.router.navigate(['/login']);
      });
  }

  /**
   * Get current JWT token
   */
  getToken(): string | null {
    if (this.isTokenExpired()) {
      this.clearAuthState();
      return null;
    }
    return localStorage.getItem(this.TOKEN_KEY);
  }

  /**
   * Check if user is authenticated
   */
  isLoggedIn(): boolean {
    return this.isAuthenticated() && !this.isTokenExpired();
  }

  /**
   * Get current user info
   */
  getUserInfo(): UserInfo | null {
    return this.currentUser();
  }

  /**
   * Get auth state as observable
   */
  getAuthState$(): Observable<AuthState> {
    return this.authState$.asObservable();
  }

  /**
   * Private: Load auth state from local storage
   */
  private loadAuthStateFromStorage(): void {
    const token = localStorage.getItem(this.TOKEN_KEY);
    const userStr = localStorage.getItem(this.USER_KEY);
    const expiresStr = localStorage.getItem(this.EXPIRES_KEY);

    if (token && userStr && expiresStr) {
      try {
        const user: UserInfo = JSON.parse(userStr);
        const expiresAt = parseInt(expiresStr, 10);

        if (!this.isTokenExpired(expiresAt)) {
          this.isAuthenticated.set(true);
          this.currentUser.set(user);
          this.authState$.next({
            isAuthenticated: true,
            user,
            token,
            expiresAt,
          });
        } else {
          this.clearAuthState();
        }
      } catch (e) {
        console.error('Failed to parse stored auth state:', e);
        this.clearAuthState();
      }
    }
  }

  /**
   * Private: Set authentication state
   */
  private setAuthState(token: string, user: UserInfo, expiresAt: number): void {
    localStorage.setItem(this.TOKEN_KEY, token);
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));
    localStorage.setItem(this.EXPIRES_KEY, expiresAt.toString());

    this.isAuthenticated.set(true);
    this.currentUser.set(user);
    this.authState$.next({
      isAuthenticated: true,
      user,
      token,
      expiresAt,
    });
  }

  /**
   * Private: Update user info
   */
  private setUserInfo(user: UserInfo, expiresAt: number): void {
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));
    localStorage.setItem(this.EXPIRES_KEY, expiresAt.toString());

    this.currentUser.set(user);
    const currentState = this.authState$.value;
    this.authState$.next({
      ...currentState,
      user,
      expiresAt,
    });
  }

  /**
   * Private: Clear authentication state
   */
  private clearAuthState(): void {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
    localStorage.removeItem(this.EXPIRES_KEY);

    this.isAuthenticated.set(false);
    this.currentUser.set(null);
    this.authState$.next({
      isAuthenticated: false,
      user: null,
      token: null,
      expiresAt: null,
    });
  }

  /**
   * Private: Check if token is expired
   */
  private isTokenExpired(expiresAt?: number): boolean {
    const expires = expiresAt || parseInt(localStorage.getItem(this.EXPIRES_KEY) || '0', 10);
    if (!expires) {
      return true;
    }

    // Add 5-minute buffer
    const now = Math.floor(Date.now() / 1000);
    return expires - 300 < now;
  }
}
