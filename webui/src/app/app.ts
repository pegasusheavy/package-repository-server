import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { SidebarComponent } from './shared/components/sidebar/sidebar.component';
import { NavbarComponent } from './shared/components/navbar/navbar.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, SidebarComponent, NavbarComponent],
  template: `
    <div class="min-h-screen bg-secondary-50">
      <!-- Sidebar -->
      <app-sidebar />

      <!-- Main Content -->
      <div class="ml-64">
        <!-- Navbar -->
        <app-navbar />

        <!-- Page Content -->
        <main class="p-6">
          <router-outlet />
        </main>
      </div>
    </div>
  `,
})
export class App {}
