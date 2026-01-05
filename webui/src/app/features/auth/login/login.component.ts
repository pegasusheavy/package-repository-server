/**
 * Login Component
 *
 * Displays SSO provider options for user authentication
 */

import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, ActivatedRoute } from '@angular/router';
import { AuthService, SsoProvider } from '../../../core/services/auth.service';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import {
  faGoogle,
  faGithub,
  faGitlab,
  faMicrosoft,
} from '@fortawesome/free-brands-svg-icons';
import { faKey, faShieldAlt, faLock } from '@fortawesome/free-solid-svg-icons';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FontAwesomeModule],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
})
export class LoginComponent implements OnInit {
  private authService = inject(AuthService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);

  providers: SsoProvider[] = [];
  loading = true;
  error: string | null = null;
  returnUrl: string = '/';

  // Icons
  faGoogle = faGoogle;
  faGithub = faGithub;
  faGitlab = faGitlab;
  faMicrosoft = faMicrosoft;
  faKey = faKey;
  faShieldAlt = faShieldAlt;
  faLock = faLock;

  ngOnInit(): void {
    // Check if already logged in
    if (this.authService.isLoggedIn()) {
      this.router.navigate(['/']);
      return;
    }

    // Get return URL from query params
    this.returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/';

    // Load available SSO providers
    this.loadProviders();
  }

  loadProviders(): void {
    this.loading = true;
    this.error = null;

    this.authService.getProviders().subscribe({
      next: (providers) => {
        this.providers = providers.filter((p) => p.enabled);
        this.loading = false;

        if (this.providers.length === 0) {
          this.error = 'No SSO providers configured. Please contact your administrator.';
        }
      },
      error: (error) => {
        console.error('Failed to load providers:', error);
        this.error = 'Failed to load authentication providers. Please try again later.';
        this.loading = false;
      },
    });
  }

  loginWithProvider(providerId: string): void {
    this.authService.loginWithProvider(providerId);
  }

  getProviderIcon(providerId: string): any {
    const iconMap: Record<string, any> = {
      google: this.faGoogle,
      github: this.faGithub,
      gitlab: this.faGitlab,
      microsoft: this.faMicrosoft,
      azure: this.faMicrosoft,
    };
    return iconMap[providerId.toLowerCase()] || this.faKey;
  }

  getProviderColor(providerId: string): string {
    const colorMap: Record<string, string> = {
      google: 'bg-red-500 hover:bg-red-600',
      github: 'bg-gray-800 hover:bg-gray-900',
      gitlab: 'bg-orange-500 hover:bg-orange-600',
      microsoft: 'bg-blue-500 hover:bg-blue-600',
      azure: 'bg-blue-600 hover:bg-blue-700',
      okta: 'bg-blue-700 hover:bg-blue-800',
      auth0: 'bg-orange-600 hover:bg-orange-700',
    };
    return colorMap[providerId.toLowerCase()] || 'bg-gray-600 hover:bg-gray-700';
  }
}
