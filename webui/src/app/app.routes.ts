import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    redirectTo: 'dashboard',
    pathMatch: 'full',
  },
  {
    path: 'dashboard',
    loadComponent: () =>
      import('./features/dashboard/dashboard.component').then((m) => m.DashboardComponent),
  },
  {
    path: 'packages',
    loadComponent: () =>
      import('./features/packages/packages.component').then((m) => m.PackagesComponent),
  },
  {
    path: 'packages/:type',
    loadComponent: () =>
      import('./features/packages/packages.component').then((m) => m.PackagesComponent),
  },
  {
    path: 'upload',
    loadComponent: () =>
      import('./features/upload/upload.component').then((m) => m.UploadComponent),
  },
  {
    path: 'settings',
    loadComponent: () =>
      import('./features/settings/settings.component').then((m) => m.SettingsComponent),
  },
  {
    path: '**',
    redirectTo: 'dashboard',
  },
];
