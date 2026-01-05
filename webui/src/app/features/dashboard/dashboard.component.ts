import { Component, inject, OnInit, signal } from '@angular/core';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import {
  faBox,
  faCubes,
  faServer,
  faHdd,
  faCheckCircle,
  faExclamationTriangle,
} from '@fortawesome/free-solid-svg-icons';
import {
  faNpm,
  faPython,
  faJava,
  faDocker,
  faRust,
  faMicrosoft,
} from '@fortawesome/free-brands-svg-icons';
import { StatCardComponent } from '../../shared/components/stat-card/stat-card.component';
import { ApiService, Package } from '../../core/services/api.service';
import { PackageCardComponent } from '../../shared/components/package-card/package-card.component';

interface RegistryStat {
  name: string;
  type: string;
  count: number;
  icon: any;
  iconBg: string;
  iconColor: string;
  route: string;
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [FontAwesomeModule, StatCardComponent, PackageCardComponent],
  template: `
    <div class="space-y-6">
      <!-- Header -->
      <div>
        <h1 class="text-2xl font-bold text-secondary-900">Dashboard</h1>
        <p class="text-secondary-500 mt-1">Overview of your package repository</p>
      </div>

      <!-- Stats Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <app-stat-card
          label="Total Packages"
          [value]="totalPackages()"
          [icon]="faBox"
          link="/packages"
          iconBgClass="bg-primary-100"
          iconClass="text-primary-600"
        />
        <app-stat-card
          label="Registries"
          [value]="registryStats().length"
          [icon]="faCubes"
          link="/packages"
          iconBgClass="bg-purple-100"
          iconClass="text-purple-600"
        />
        <app-stat-card
          label="Server Status"
          [value]="serverStatus()"
          [icon]="faServer"
          link="/settings"
          [iconBgClass]="serverStatus() === 'Healthy' ? 'bg-green-100' : 'bg-red-100'"
          [iconClass]="serverStatus() === 'Healthy' ? 'text-green-600' : 'text-red-600'"
        />
        <app-stat-card
          label="Storage"
          [value]="storageType()"
          [icon]="faHdd"
          link="/settings"
          iconBgClass="bg-secondary-100"
          iconClass="text-secondary-600"
        />
      </div>

      <!-- Registry Stats -->
      <div>
        <h2 class="text-lg font-semibold text-secondary-900 mb-4">Registries</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
          @for (registry of registryStats(); track registry.type) {
            <app-stat-card
              [label]="registry.name"
              [value]="registry.count"
              [icon]="registry.icon"
              [link]="registry.route"
              [iconBgClass]="registry.iconBg"
              [iconClass]="registry.iconColor"
              subtitle="packages"
            />
          }
        </div>
      </div>

      <!-- Recent Packages -->
      <div>
        <h2 class="text-lg font-semibold text-secondary-900 mb-4">Recent Packages</h2>
        @if (recentPackages().length === 0) {
          <div class="bg-white rounded-lg border border-secondary-200 p-8 text-center">
            <fa-icon [icon]="faBox" class="text-4xl text-secondary-300"></fa-icon>
            <p class="mt-4 text-secondary-500">No packages yet</p>
            <p class="text-sm text-secondary-400">Upload your first package to get started</p>
          </div>
        } @else {
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            @for (pkg of recentPackages(); track pkg.filename) {
              <app-package-card [pkg]="pkg" [showDelete]="false" [showDownload]="false" />
            }
          </div>
        }
      </div>

      <!-- Quick Actions -->
      <div>
        <h2 class="text-lg font-semibold text-secondary-900 mb-4">Quick Actions</h2>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <a
            routerLink="/upload"
            class="flex items-center gap-4 p-4 bg-white rounded-lg border border-secondary-200 hover:border-primary-300 hover:shadow-md transition-all"
          >
            <div class="w-12 h-12 rounded-lg bg-green-100 flex items-center justify-center">
              <fa-icon [icon]="faBox" class="text-green-600 text-xl"></fa-icon>
            </div>
            <div>
              <h3 class="font-semibold text-secondary-900">Upload Package</h3>
              <p class="text-sm text-secondary-500">Add a new package to the repository</p>
            </div>
          </a>
          <a
            routerLink="/settings"
            class="flex items-center gap-4 p-4 bg-white rounded-lg border border-secondary-200 hover:border-primary-300 hover:shadow-md transition-all"
          >
            <div class="w-12 h-12 rounded-lg bg-blue-100 flex items-center justify-center">
              <fa-icon [icon]="faServer" class="text-blue-600 text-xl"></fa-icon>
            </div>
            <div>
              <h3 class="font-semibold text-secondary-900">Setup Instructions</h3>
              <p class="text-sm text-secondary-500">Configure clients to use this repository</p>
            </div>
          </a>
          <div
            class="flex items-center gap-4 p-4 bg-white rounded-lg border border-secondary-200"
          >
            <div
              class="w-12 h-12 rounded-lg flex items-center justify-center"
              [class]="serverStatus() === 'Healthy' ? 'bg-green-100' : 'bg-red-100'"
            >
              <fa-icon
                [icon]="serverStatus() === 'Healthy' ? faCheckCircle : faExclamationTriangle"
                [class]="serverStatus() === 'Healthy' ? 'text-green-600' : 'text-red-600'"
                class="text-xl"
              ></fa-icon>
            </div>
            <div>
              <h3 class="font-semibold text-secondary-900">Server Health</h3>
              <p class="text-sm" [class]="serverStatus() === 'Healthy' ? 'text-green-600' : 'text-red-600'">
                {{ serverStatus() }}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
})
export class DashboardComponent implements OnInit {
  private apiService = inject(ApiService);

  faBox = faBox;
  faCubes = faCubes;
  faServer = faServer;
  faHdd = faHdd;
  faCheckCircle = faCheckCircle;
  faExclamationTriangle = faExclamationTriangle;

  totalPackages = signal(0);
  serverStatus = signal<string>('Checking...');
  storageType = signal<string>('Local');
  recentPackages = signal<Package[]>([]);

  registryStats = signal<RegistryStat[]>([
    { name: 'Cargo', type: 'cargo', count: 0, icon: faRust, iconBg: 'bg-orange-100', iconColor: 'text-orange-600', route: '/packages/cargo' },
    { name: 'npm', type: 'npm', count: 0, icon: faNpm, iconBg: 'bg-red-100', iconColor: 'text-red-600', route: '/packages/npm' },
    { name: 'PyPI', type: 'pypi', count: 0, icon: faPython, iconBg: 'bg-blue-100', iconColor: 'text-blue-600', route: '/packages/pypi' },
    { name: 'Maven', type: 'maven', count: 0, icon: faJava, iconBg: 'bg-red-100', iconColor: 'text-red-700', route: '/packages/maven' },
    { name: 'Docker', type: 'docker', count: 0, icon: faDocker, iconBg: 'bg-sky-100', iconColor: 'text-sky-600', route: '/packages/docker' },
    { name: 'NuGet', type: 'nuget', count: 0, icon: faMicrosoft, iconBg: 'bg-blue-100', iconColor: 'text-blue-700', route: '/packages/nuget' },
    { name: 'DEB', type: 'deb', count: 0, icon: faCubes, iconBg: 'bg-purple-100', iconColor: 'text-purple-600', route: '/packages/deb' },
    { name: 'RPM', type: 'rpm', count: 0, icon: faCubes, iconBg: 'bg-red-100', iconColor: 'text-red-600', route: '/packages/rpm' },
    { name: 'Arch', type: 'arch', count: 0, icon: faCubes, iconBg: 'bg-cyan-100', iconColor: 'text-cyan-600', route: '/packages/arch' },
    { name: 'Alpine', type: 'alpine', count: 0, icon: faCubes, iconBg: 'bg-blue-100', iconColor: 'text-blue-600', route: '/packages/alpine' },
  ]);

  ngOnInit() {
    this.loadData();
  }

  loadData() {
    // Load health status
    this.apiService.getHealth().subscribe({
      next: (health) => {
        this.serverStatus.set('Healthy');
        this.storageType.set(health.storage || 'Local');
      },
      error: () => this.serverStatus.set('Unhealthy'),
    });

    // Load packages
    this.apiService.listPackages({ per_page: 6 }).subscribe({
      next: (response) => {
        this.totalPackages.set(response.total);
        this.recentPackages.set(response.packages);
      },
      error: () => {},
    });

    // Load stats per registry type
    const types = ['deb', 'rpm', 'arch', 'alpine'];
    types.forEach((type) => {
      this.apiService.listPackagesByType(type, { per_page: 1 }).subscribe({
        next: (response) => {
          this.updateRegistryStat(type, response.total);
        },
        error: () => {},
      });
    });
  }

  private updateRegistryStat(type: string, count: number) {
    const stats = this.registryStats();
    const index = stats.findIndex((s) => s.type === type);
    if (index !== -1) {
      stats[index].count = count;
      this.registryStats.set([...stats]);
    }
  }
}
