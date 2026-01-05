import { Component, input, output } from '@angular/core';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { faTrash, faDownload, faCube } from '@fortawesome/free-solid-svg-icons';
import { Package } from '../../../core/services/api.service';

@Component({
  selector: 'app-package-card',
  standalone: true,
  imports: [FontAwesomeModule],
  template: `
    <div
      class="bg-white rounded-lg border border-secondary-200 p-4 hover:shadow-md transition-shadow"
    >
      <div class="flex items-start justify-between">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-secondary-100 flex items-center justify-center">
            <fa-icon [icon]="faCube" class="text-secondary-500"></fa-icon>
          </div>
          <div>
            <h3 class="font-semibold text-secondary-900">{{ pkg().name }}</h3>
            <p class="text-sm text-secondary-500">{{ pkg().version }}</p>
          </div>
        </div>
        <div class="flex items-center gap-2">
          @if (showDownload()) {
            <button
              (click)="download.emit(pkg())"
              class="p-2 text-secondary-400 hover:text-primary-500 transition-colors"
              title="Download"
            >
              <fa-icon [icon]="faDownload"></fa-icon>
            </button>
          }
          @if (showDelete()) {
            <button
              (click)="delete.emit(pkg())"
              class="p-2 text-secondary-400 hover:text-red-500 transition-colors"
              title="Delete"
            >
              <fa-icon [icon]="faTrash"></fa-icon>
            </button>
          }
        </div>
      </div>

      <div class="mt-4 flex flex-wrap gap-2">
        <span
          class="px-2 py-1 text-xs font-medium rounded-full bg-secondary-100 text-secondary-600"
        >
          {{ pkg().architecture }}
        </span>
        <span class="px-2 py-1 text-xs font-medium rounded-full bg-primary-100 text-primary-600">
          {{ pkg().package_type }}
        </span>
        <span class="px-2 py-1 text-xs font-medium rounded-full bg-secondary-100 text-secondary-500">
          {{ formatSize(pkg().size) }}
        </span>
      </div>

      <p class="mt-3 text-xs text-secondary-400 truncate" title="{{ pkg().filename }}">
        {{ pkg().filename }}
      </p>
    </div>
  `,
})
export class PackageCardComponent {
  pkg = input.required<Package>();
  showDownload = input<boolean>(true);
  showDelete = input<boolean>(true);

  download = output<Package>();
  delete = output<Package>();

  faCube = faCube;
  faTrash = faTrash;
  faDownload = faDownload;

  formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }
}
