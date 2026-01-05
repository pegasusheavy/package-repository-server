/**
 * OAuth Callback Component
 *
 * Handles OAuth redirect after successful authentication
 */

import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { faSpinner, faCheckCircle, faExclamationCircle } from '@fortawesome/free-solid-svg-icons';

@Component({
  selector: 'app-callback',
  standalone: true,
  imports: [CommonModule, FontAwesomeModule],
  templateUrl: './callback.component.html',
  styleUrls: ['./callback.component.css'],
})
export class CallbackComponent implements OnInit {
  private authService = inject(AuthService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);

  loading = true;
  success = false;
  error: string | null = null;

  faSpinner = faSpinner;
  faCheckCircle = faCheckCircle;
  faExclamationCircle = faExclamationCircle;

  ngOnInit(): void {
    // Extract OAuth parameters from URL
    const code = this.route.snapshot.queryParams['code'];
    const state = this.route.snapshot.queryParams['state'];
    const providerId = this.route.snapshot.params['provider'];

    if (!code || !state) {
      this.error = 'Invalid OAuth callback - missing parameters';
      this.loading = false;
      return;
    }

    // Handle OAuth callback
    this.authService.handleCallback(providerId, code, state).subscribe({
      next: (success) => {
        if (success) {
          this.success = true;
          this.loading = false;

          // Redirect to home or return URL after 1 second
          setTimeout(() => {
            const returnUrl = sessionStorage.getItem('returnUrl') || '/';
            sessionStorage.removeItem('returnUrl');
            this.router.navigate([returnUrl]);
          }, 1000);
        } else {
          this.error = 'Authentication failed';
          this.loading = false;
        }
      },
      error: (error) => {
        console.error('OAuth callback error:', error);
        this.error = error.error?.error || 'Authentication failed. Please try again.';
        this.loading = false;

        // Redirect to login after 3 seconds
        setTimeout(() => {
          this.router.navigate(['/login']);
        }, 3000);
      },
    });
  }
}
