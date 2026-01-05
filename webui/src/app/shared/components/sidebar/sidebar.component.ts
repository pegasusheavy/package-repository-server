import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import {
  faHome,
  faUpload,
  faCog,
  faCubes,
  faServer,
} from '@fortawesome/free-solid-svg-icons';
import {
  faNpm,
  faPython,
  faJava,
  faDocker as faDockerBrand,
  faRust as faRustBrand,
  faMicrosoft,
} from '@fortawesome/free-brands-svg-icons';

interface NavItem {
  label: string;
  route: string;
  icon: any;
}

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive, FontAwesomeModule],
  template: `
    <aside class="fixed left-0 top-0 h-full w-64 bg-secondary-800 text-white flex flex-col">
      <!-- Logo -->
      <div class="p-6 border-b border-secondary-700">
        <h1 class="text-xl font-bold flex items-center gap-2">
          <fa-icon [icon]="faServer" class="text-primary-400"></fa-icon>
          <span>Package Repo</span>
        </h1>
        <p class="text-xs text-secondary-400 mt-1">Management Console</p>
      </div>

      <!-- Navigation -->
      <nav class="flex-1 py-4 overflow-y-auto">
        <div class="px-3 mb-2">
          <span class="text-xs font-semibold text-secondary-500 uppercase tracking-wider"
            >Overview</span
          >
        </div>
        @for (item of mainNav; track item.route) {
          <a
            [routerLink]="item.route"
            routerLinkActive="bg-secondary-700 border-r-2 border-primary-500"
            class="flex items-center gap-3 px-6 py-3 text-secondary-300 hover:bg-secondary-700 hover:text-white transition-colors"
          >
            <fa-icon [icon]="item.icon" class="w-5"></fa-icon>
            <span>{{ item.label }}</span>
          </a>
        }

        <div class="px-3 mt-6 mb-2">
          <span class="text-xs font-semibold text-secondary-500 uppercase tracking-wider"
            >Registries</span
          >
        </div>
        @for (item of registryNav; track item.route) {
          <a
            [routerLink]="item.route"
            routerLinkActive="bg-secondary-700 border-r-2 border-primary-500"
            class="flex items-center gap-3 px-6 py-3 text-secondary-300 hover:bg-secondary-700 hover:text-white transition-colors"
          >
            <fa-icon [icon]="item.icon" class="w-5"></fa-icon>
            <span>{{ item.label }}</span>
          </a>
        }

        <div class="px-3 mt-6 mb-2">
          <span class="text-xs font-semibold text-secondary-500 uppercase tracking-wider"
            >System Packages</span
          >
        </div>
        @for (item of systemNav; track item.route) {
          <a
            [routerLink]="item.route"
            routerLinkActive="bg-secondary-700 border-r-2 border-primary-500"
            class="flex items-center gap-3 px-6 py-3 text-secondary-300 hover:bg-secondary-700 hover:text-white transition-colors"
          >
            <fa-icon [icon]="item.icon" class="w-5"></fa-icon>
            <span>{{ item.label }}</span>
          </a>
        }
      </nav>

      <!-- Footer -->
      <div class="p-4 border-t border-secondary-700">
        <a
          routerLink="/settings"
          routerLinkActive="text-primary-400"
          class="flex items-center gap-3 text-secondary-400 hover:text-white transition-colors"
        >
          <fa-icon [icon]="faCog"></fa-icon>
          <span>Settings</span>
        </a>
      </div>
    </aside>
  `,
})
export class SidebarComponent {
  faServer = faServer;
  faCog = faCog;

  mainNav: NavItem[] = [
    { label: 'Dashboard', route: '/dashboard', icon: faHome },
    { label: 'Upload', route: '/upload', icon: faUpload },
  ];

  registryNav: NavItem[] = [
    { label: 'Cargo', route: '/packages/cargo', icon: faRustBrand },
    { label: 'npm', route: '/packages/npm', icon: faNpm },
    { label: 'PyPI', route: '/packages/pypi', icon: faPython },
    { label: 'Maven', route: '/packages/maven', icon: faJava },
    { label: 'Docker', route: '/packages/docker', icon: faDockerBrand },
    { label: 'NuGet', route: '/packages/nuget', icon: faMicrosoft },
  ];

  systemNav: NavItem[] = [
    { label: 'DEB', route: '/packages/deb', icon: faCubes },
    { label: 'RPM', route: '/packages/rpm', icon: faCubes },
    { label: 'Arch', route: '/packages/arch', icon: faCubes },
    { label: 'Alpine', route: '/packages/alpine', icon: faCubes },
  ];
}
