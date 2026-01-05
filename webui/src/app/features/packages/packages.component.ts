import { Component, inject, OnInit, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import {
  faSearch,
  faRefresh,
  faFilter,
  faCubes,
  faChevronLeft,
  faChevronRight,
} from '@fortawesome/free-solid-svg-icons';
import { ApiService, Package } from '../../core/services/api.service';
import { PackageCardComponent } from '../../shared/components/package-card/package-card.component';

@Component({
  selector: 'app-packages',
  standalone: true,
  imports: [FormsModule, FontAwesomeModule, PackageCardComponent],
  template: `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-secondary-900">{{ title() }}</h1>
          <p class="text-secondary-500 mt-1">{{ total() }} packages found</p>
        </div>
        <div class="flex items-center gap-2">
          <button
            (click)="rebuildRepo()"
            [disabled]="rebuilding()"
            class="px-4 py-2 bg-secondary-100 text-secondary-700 rounded-lg hover:bg-secondary-200 transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            <fa-icon [icon]="faRefresh" [class.animate-spin]="rebuilding()"></fa-icon>
            Rebuild Index
          </button>
        </div>
      </div>

      <!-- Filters -->
      <div class="bg-white rounded-lg border border-secondary-200 p-4">
        <div class="flex flex-wrap items-center gap-4">
          <!-- Search -->
          <div class="flex-1 min-w-[200px]">
            <div class="relative">
              <fa-icon
                [icon]="faSearch"
                class="absolute left-3 top-1/2 -translate-y-1/2 text-secondary-400"
              ></fa-icon>
              <input
                type="text"
                [(ngModel)]="searchTerm"
                (ngModelChange)="onSearch()"
                placeholder="Search packages..."
                class="w-full pl-10 pr-4 py-2 border border-secondary-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </div>
          </div>

          <!-- Architecture Filter -->
          <div class="flex items-center gap-2">
            <fa-icon [icon]="faFilter" class="text-secondary-400"></fa-icon>
            <select
              [(ngModel)]="selectedArch"
              (ngModelChange)="loadPackages()"
              class="px-3 py-2 border border-secondary-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <option value="">All Architectures</option>
              <option value="amd64">amd64</option>
              <option value="arm64">arm64</option>
              <option value="x86_64">x86_64</option>
              <option value="aarch64">aarch64</option>
              <option value="noarch">noarch</option>
              <option value="all">all</option>
              <option value="any">any</option>
            </select>
          </div>

          <!-- Per Page -->
          <select
            [(ngModel)]="perPage"
            (ngModelChange)="loadPackages()"
            class="px-3 py-2 border border-secondary-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option [value]="12">12 per page</option>
            <option [value]="24">24 per page</option>
            <option [value]="48">48 per page</option>
          </select>
        </div>
      </div>

      <!-- Loading State -->
      @if (loading()) {
        <div class="flex items-center justify-center py-12">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
        </div>
      } @else if (packages().length === 0) {
        <!-- Empty State -->
        <div class="bg-white rounded-lg border border-secondary-200 p-12 text-center">
          <fa-icon [icon]="faCubes" class="text-5xl text-secondary-300"></fa-icon>
          <h3 class="mt-4 text-lg font-semibold text-secondary-700">No packages found</h3>
          <p class="mt-2 text-secondary-500">
            @if (pkgType()) {
              No {{ pkgType() }} packages have been uploaded yet.
            } @else {
              No packages match your search criteria.
            }
          </p>
        </div>
      } @else {
        <!-- Package Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          @for (pkg of packages(); track pkg.filename) {
            <app-package-card
              [pkg]="pkg"
              (delete)="deletePackage($event)"
              (download)="downloadPackage($event)"
            />
          }
        </div>

        <!-- Pagination -->
        @if (totalPages() > 1) {
          <div class="flex items-center justify-center gap-2">
            <button
              (click)="prevPage()"
              [disabled]="currentPage() === 1"
              class="p-2 rounded-lg border border-secondary-300 hover:bg-secondary-100 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <fa-icon [icon]="faChevronLeft"></fa-icon>
            </button>
            <span class="px-4 py-2 text-secondary-600">
              Page {{ currentPage() }} of {{ totalPages() }}
            </span>
            <button
              (click)="nextPage()"
              [disabled]="currentPage() === totalPages()"
              class="p-2 rounded-lg border border-secondary-300 hover:bg-secondary-100 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <fa-icon [icon]="faChevronRight"></fa-icon>
            </button>
          </div>
        }
      }

      <!-- Delete Confirmation Modal -->
      @if (showDeleteModal()) {
        <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 class="text-lg font-semibold text-secondary-900">Delete Package</h3>
            <p class="mt-2 text-secondary-600">
              Are you sure you want to delete <strong>{{ packageToDelete()?.name }}</strong>? This
              action cannot be undone.
            </p>
            <div class="mt-6 flex justify-end gap-3">
              <button
                (click)="cancelDelete()"
                class="px-4 py-2 text-secondary-700 hover:bg-secondary-100 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                (click)="confirmDelete()"
                class="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      }
    </div>
  `,
})
export class PackagesComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private apiService = inject(ApiService);

  faSearch = faSearch;
  faRefresh = faRefresh;
  faFilter = faFilter;
  faCubes = faCubes;
  faChevronLeft = faChevronLeft;
  faChevronRight = faChevronRight;

  pkgType = signal<string | null>(null);
  title = signal('All Packages');
  packages = signal<Package[]>([]);
  loading = signal(false);
  rebuilding = signal(false);
  total = signal(0);
  currentPage = signal(1);
  perPage = 12;
  searchTerm = '';
  selectedArch = '';

  showDeleteModal = signal(false);
  packageToDelete = signal<Package | null>(null);

  totalPages = signal(1);

  ngOnInit() {
    this.route.params.subscribe((params) => {
      const type = params['type'];
      this.pkgType.set(type || null);
      this.title.set(type ? this.formatTitle(type) : 'All Packages');
      this.currentPage.set(1);
      this.loadPackages();
    });
  }

  formatTitle(type: string): string {
    const titles: Record<string, string> = {
      deb: 'Debian Packages',
      rpm: 'RPM Packages',
      arch: 'Arch Packages',
      alpine: 'Alpine Packages',
      cargo: 'Cargo Crates',
      npm: 'npm Packages',
      pypi: 'PyPI Packages',
      maven: 'Maven Artifacts',
      docker: 'Docker Images',
      nuget: 'NuGet Packages',
    };
    return titles[type] || type;
  }

  loadPackages() {
    this.loading.set(true);
    const params = {
      page: this.currentPage(),
      per_page: this.perPage,
      arch: this.selectedArch || undefined,
    };

    const request = this.pkgType()
      ? this.apiService.listPackagesByType(this.pkgType()!, params)
      : this.apiService.listPackages(params);

    request.subscribe({
      next: (response) => {
        this.packages.set(response.packages);
        this.total.set(response.total);
        this.totalPages.set(Math.ceil(response.total / this.perPage));
        this.loading.set(false);
      },
      error: () => {
        this.packages.set([]);
        this.loading.set(false);
      },
    });
  }

  onSearch() {
    // Client-side filtering for now
    // In a real app, you'd send this to the server
    this.loadPackages();
  }

  rebuildRepo() {
    if (!this.pkgType()) return;

    this.rebuilding.set(true);
    this.apiService.rebuildRepo(this.pkgType()!).subscribe({
      next: () => {
        this.rebuilding.set(false);
        this.loadPackages();
      },
      error: () => {
        this.rebuilding.set(false);
      },
    });
  }

  deletePackage(pkg: Package) {
    this.packageToDelete.set(pkg);
    this.showDeleteModal.set(true);
  }

  cancelDelete() {
    this.showDeleteModal.set(false);
    this.packageToDelete.set(null);
  }

  confirmDelete() {
    const pkg = this.packageToDelete();
    if (!pkg) return;

    this.apiService.deletePackage(pkg.package_type, pkg.name).subscribe({
      next: () => {
        this.showDeleteModal.set(false);
        this.packageToDelete.set(null);
        this.loadPackages();
      },
      error: () => {
        this.showDeleteModal.set(false);
        this.packageToDelete.set(null);
      },
    });
  }

  downloadPackage(pkg: Package) {
    // Open download URL in new tab
    window.open(`/api/v1/packages/${pkg.package_type}/${pkg.filename}`, '_blank');
  }

  prevPage() {
    if (this.currentPage() > 1) {
      this.currentPage.update((p) => p - 1);
      this.loadPackages();
    }
  }

  nextPage() {
    if (this.currentPage() < this.totalPages()) {
      this.currentPage.update((p) => p + 1);
      this.loadPackages();
    }
  }
}
