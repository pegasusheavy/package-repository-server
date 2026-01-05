import { Component, inject, signal } from '@angular/core';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import {
  faCopy,
  faCheckCircle,
  faTerminal,
  faBook,
} from '@fortawesome/free-solid-svg-icons';
import {
  faNpm,
  faPython,
  faJava,
  faDocker,
  faRust,
  faMicrosoft,
  faUbuntu,
  faFedora,
  faLinux,
} from '@fortawesome/free-brands-svg-icons';
import { ApiService } from '../../core/services/api.service';

interface SetupTab {
  id: string;
  label: string;
  icon: any;
  description: string;
}

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [FontAwesomeModule],
  template: `
    <div class="space-y-6">
      <!-- Header -->
      <div>
        <h1 class="text-2xl font-bold text-secondary-900">Settings & Setup</h1>
        <p class="text-secondary-500 mt-1">Configure clients to use this package repository</p>
      </div>

      <!-- Setup Instructions -->
      <div class="bg-white rounded-lg border border-secondary-200">
        <!-- Tabs -->
        <div class="border-b border-secondary-200 overflow-x-auto">
          <div class="flex min-w-max">
            @for (tab of tabs; track tab.id) {
              <button
                (click)="selectTab(tab.id)"
                class="px-4 py-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 whitespace-nowrap"
                [class]="
                  selectedTab() === tab.id
                    ? 'border-primary-500 text-primary-600'
                    : 'border-transparent text-secondary-500 hover:text-secondary-700 hover:border-secondary-300'
                "
              >
                <fa-icon [icon]="tab.icon"></fa-icon>
                {{ tab.label }}
              </button>
            }
          </div>
        </div>

        <!-- Tab Content -->
        <div class="p-6">
          @if (loading()) {
            <div class="flex items-center justify-center py-8">
              <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
            </div>
          } @else {
            <div class="mb-4">
              <h3 class="font-semibold text-secondary-900">{{ getTabDescription() }}</h3>
            </div>

            <!-- Code Block -->
            <div class="relative">
              <div class="absolute top-3 right-3 flex gap-2">
                <button
                  (click)="copyToClipboard()"
                  class="p-2 text-secondary-400 hover:text-secondary-600 bg-secondary-800 rounded-lg transition-colors"
                  [title]="copied() ? 'Copied!' : 'Copy to clipboard'"
                >
                  @if (copied()) {
                    <fa-icon [icon]="faCheckCircle" class="text-green-400"></fa-icon>
                  } @else {
                    <fa-icon [icon]="faCopy"></fa-icon>
                  }
                </button>
              </div>
              <pre
                class="bg-secondary-900 text-secondary-100 p-4 rounded-lg overflow-x-auto text-sm font-mono leading-relaxed"
              ><code>{{ setupContent() }}</code></pre>
            </div>

            <!-- Additional Info -->
            <div class="mt-6 p-4 bg-secondary-50 rounded-lg">
              <div class="flex items-start gap-3">
                <fa-icon [icon]="faBook" class="text-secondary-400 mt-0.5"></fa-icon>
                <div>
                  <h4 class="font-medium text-secondary-700">Need help?</h4>
                  <p class="text-sm text-secondary-500 mt-1">
                    Replace <code class="bg-secondary-200 px-1 rounded">YOUR_API_KEY_HERE</code> with
                    your actual API key. Contact your administrator if you don't have one.
                  </p>
                </div>
              </div>
            </div>
          }
        </div>
      </div>

      <!-- Server Info -->
      <div class="bg-white rounded-lg border border-secondary-200 p-6">
        <h3 class="font-semibold text-secondary-900 mb-4">Server Information</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label class="text-sm text-secondary-500">Base URL</label>
            <div class="mt-1 flex items-center gap-2">
              <code class="flex-1 px-3 py-2 bg-secondary-100 rounded text-sm">{{
                getBaseUrl()
              }}</code>
              <button
                (click)="copyUrl()"
                class="p-2 text-secondary-400 hover:text-secondary-600"
              >
                <fa-icon [icon]="faCopy"></fa-icon>
              </button>
            </div>
          </div>
          <div>
            <label class="text-sm text-secondary-500">Health Endpoint</label>
            <div class="mt-1">
              <code class="px-3 py-2 bg-secondary-100 rounded text-sm block"
                >{{ getBaseUrl() }}/health</code
              >
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Reference -->
      <div class="bg-white rounded-lg border border-secondary-200 p-6">
        <h3 class="font-semibold text-secondary-900 mb-4">Quick Reference</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          @for (ref of quickRefs; track ref.type) {
            <div class="p-4 border border-secondary-200 rounded-lg">
              <div class="flex items-center gap-2 mb-2">
                <fa-icon [icon]="ref.icon" [class]="ref.iconClass"></fa-icon>
                <span class="font-medium text-secondary-700">{{ ref.label }}</span>
              </div>
              <code class="text-xs text-secondary-500 block">{{ ref.command }}</code>
            </div>
          }
        </div>
      </div>
    </div>
  `,
})
export class SettingsComponent {
  private apiService = inject(ApiService);

  faCopy = faCopy;
  faCheckCircle = faCheckCircle;
  faTerminal = faTerminal;
  faBook = faBook;

  selectedTab = signal('apt');
  setupContent = signal('');
  loading = signal(false);
  copied = signal(false);

  tabs: SetupTab[] = [
    { id: 'apt', label: 'APT/Debian', icon: faUbuntu, description: 'Setup for Debian/Ubuntu systems' },
    { id: 'rpm', label: 'YUM/DNF', icon: faFedora, description: 'Setup for RHEL/Fedora/CentOS systems' },
    { id: 'arch', label: 'Pacman', icon: faLinux, description: 'Setup for Arch Linux systems' },
    { id: 'alpine', label: 'APK', icon: faLinux, description: 'Setup for Alpine Linux systems' },
    { id: 'cargo', label: 'Cargo', icon: faRust, description: 'Rust Cargo registry configuration' },
    { id: 'npm', label: 'npm', icon: faNpm, description: 'npm registry configuration' },
    { id: 'pypi', label: 'PyPI', icon: faPython, description: 'Python pip/twine configuration' },
    { id: 'maven', label: 'Maven', icon: faJava, description: 'Maven/Gradle repository configuration' },
    { id: 'docker', label: 'Docker', icon: faDocker, description: 'Docker registry configuration' },
    { id: 'nuget', label: 'NuGet', icon: faMicrosoft, description: '.NET NuGet registry configuration' },
  ];

  quickRefs = [
    { type: 'apt', label: 'Debian/Ubuntu', icon: faUbuntu, iconClass: 'text-orange-500', command: 'curl -fsSL /setup/apt | sudo bash' },
    { type: 'rpm', label: 'RHEL/Fedora', icon: faFedora, iconClass: 'text-blue-500', command: 'curl -fsSL /setup/rpm | sudo bash' },
    { type: 'cargo', label: 'Cargo', icon: faRust, iconClass: 'text-orange-600', command: 'cargo publish --registry private' },
    { type: 'npm', label: 'npm', icon: faNpm, iconClass: 'text-red-500', command: 'npm publish --registry <url>' },
    { type: 'pypi', label: 'PyPI', icon: faPython, iconClass: 'text-blue-500', command: 'twine upload --repository private dist/*' },
    { type: 'docker', label: 'Docker', icon: faDocker, iconClass: 'text-sky-500', command: 'docker push <host>/image:tag' },
  ];

  constructor() {
    this.loadSetupContent();
  }

  selectTab(tabId: string) {
    this.selectedTab.set(tabId);
    this.loadSetupContent();
  }

  getTabDescription(): string {
    const tab = this.tabs.find((t) => t.id === this.selectedTab());
    return tab?.description || '';
  }

  loadSetupContent() {
    this.loading.set(true);
    this.apiService.getSetupScript(this.selectedTab()).subscribe({
      next: (content) => {
        this.setupContent.set(content);
        this.loading.set(false);
      },
      error: () => {
        this.setupContent.set('Failed to load setup instructions');
        this.loading.set(false);
      },
    });
  }

  copyToClipboard() {
    navigator.clipboard.writeText(this.setupContent()).then(() => {
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), 2000);
    });
  }

  copyUrl() {
    navigator.clipboard.writeText(this.getBaseUrl());
  }

  getBaseUrl(): string {
    return window.location.origin;
  }
}
