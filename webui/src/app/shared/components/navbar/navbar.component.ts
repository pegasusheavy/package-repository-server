import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import {
  faKey,
  faSignOutAlt,
  faCheckCircle,
  faExclamationCircle,
} from '@fortawesome/free-solid-svg-icons';
import { AuthService } from '../../../core/services/auth.service';
import { ApiService } from '../../../core/services/api.service';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [FormsModule, FontAwesomeModule],
  template: `
    <header class="h-16 bg-white border-b border-secondary-200 flex items-center justify-between px-6">
      <div class="flex items-center gap-4">
        <h2 class="text-lg font-semibold text-secondary-800">{{ title }}</h2>
      </div>

      <div class="flex items-center gap-4">
        <!-- Health Status -->
        <div class="flex items-center gap-2 text-sm">
          @if (healthStatus() === 'healthy') {
            <fa-icon [icon]="faCheckCircle" class="text-green-500"></fa-icon>
            <span class="text-green-600">Healthy</span>
          } @else if (healthStatus() === 'unhealthy') {
            <fa-icon [icon]="faExclamationCircle" class="text-red-500"></fa-icon>
            <span class="text-red-600">Unhealthy</span>
          } @else {
            <span class="text-secondary-400">Checking...</span>
          }
        </div>

        <div class="h-6 w-px bg-secondary-200"></div>

        <!-- API Key Input -->
        @if (!authService.isAuthenticated()) {
          <div class="flex items-center gap-2">
            <fa-icon [icon]="faKey" class="text-secondary-400"></fa-icon>
            <input
              type="password"
              [(ngModel)]="apiKeyInput"
              placeholder="Enter API Key"
              class="px-3 py-1.5 text-sm border border-secondary-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
            />
            <button
              (click)="setApiKey()"
              class="px-3 py-1.5 text-sm bg-primary-500 text-white rounded-md hover:bg-primary-600 transition-colors"
            >
              Connect
            </button>
          </div>
        } @else {
          <div class="flex items-center gap-2">
            <span class="text-sm text-green-600 flex items-center gap-1">
              <fa-icon [icon]="faCheckCircle"></fa-icon>
              Connected
            </span>
            <button
              (click)="logout()"
              class="p-2 text-secondary-500 hover:text-red-500 transition-colors"
              title="Disconnect"
            >
              <fa-icon [icon]="faSignOutAlt"></fa-icon>
            </button>
          </div>
        }
      </div>
    </header>
  `,
})
export class NavbarComponent {
  authService = inject(AuthService);
  private apiService = inject(ApiService);

  faKey = faKey;
  faSignOutAlt = faSignOutAlt;
  faCheckCircle = faCheckCircle;
  faExclamationCircle = faExclamationCircle;

  title = 'Package Repository';
  apiKeyInput = '';
  healthStatus = signal<'healthy' | 'unhealthy' | 'checking'>('checking');

  constructor() {
    this.checkHealth();
  }

  checkHealth() {
    this.apiService.getHealth().subscribe({
      next: () => this.healthStatus.set('healthy'),
      error: () => this.healthStatus.set('unhealthy'),
    });
  }

  setApiKey() {
    if (this.apiKeyInput.trim()) {
      this.authService.setApiKey(this.apiKeyInput.trim());
      this.apiKeyInput = '';
    }
  }

  logout() {
    this.authService.clearApiKey();
  }
}
