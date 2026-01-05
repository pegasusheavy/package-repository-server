import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import {
  faUpload,
  faFile,
  faCheckCircle,
  faExclamationCircle,
  faTimes,
  faSpinner,
} from '@fortawesome/free-solid-svg-icons';
import { ApiService } from '../../core/services/api.service';

interface UploadFile {
  file: File;
  progress: number;
  status: 'pending' | 'uploading' | 'success' | 'error';
  message?: string;
  pkgType: string;
}

@Component({
  selector: 'app-upload',
  standalone: true,
  imports: [FormsModule, FontAwesomeModule],
  template: `
    <div class="space-y-6">
      <!-- Header -->
      <div>
        <h1 class="text-2xl font-bold text-secondary-900">Upload Package</h1>
        <p class="text-secondary-500 mt-1">Upload packages to the repository</p>
      </div>

      <!-- Package Type Selection -->
      <div class="bg-white rounded-lg border border-secondary-200 p-6">
        <label class="block text-sm font-medium text-secondary-700 mb-2">Package Type</label>
        <select
          [(ngModel)]="selectedType"
          class="w-full md:w-auto px-4 py-2 border border-secondary-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
        >
          <option value="deb">Debian (.deb)</option>
          <option value="rpm">RPM (.rpm)</option>
          <option value="arch">Arch (.pkg.tar.zst)</option>
          <option value="alpine">Alpine (.apk)</option>
        </select>
        <p class="mt-2 text-sm text-secondary-500">
          For Cargo, npm, PyPI, Maven, Docker, and NuGet, use the native CLI tools with the setup
          instructions from the Settings page.
        </p>
      </div>

      <!-- Drop Zone -->
      <div
        class="bg-white rounded-lg border-2 border-dashed transition-colors p-12 text-center"
        [class]="isDragging() ? 'border-primary-500 bg-primary-50' : 'border-secondary-300'"
        (dragover)="onDragOver($event)"
        (dragleave)="onDragLeave($event)"
        (drop)="onDrop($event)"
      >
        <input
          type="file"
          #fileInput
          (change)="onFileSelect($event)"
          [accept]="acceptedExtensions()"
          multiple
          class="hidden"
        />
        <fa-icon [icon]="faUpload" class="text-5xl text-secondary-400"></fa-icon>
        <h3 class="mt-4 text-lg font-semibold text-secondary-700">
          Drag & drop files here
        </h3>
        <p class="mt-2 text-secondary-500">
          or
          <button
            (click)="fileInput.click()"
            class="text-primary-500 hover:text-primary-600 font-medium"
          >
            browse files
          </button>
        </p>
        <p class="mt-4 text-sm text-secondary-400">
          Accepted: {{ acceptedExtensions() }}
        </p>
      </div>

      <!-- Upload Queue -->
      @if (uploadQueue().length > 0) {
        <div class="bg-white rounded-lg border border-secondary-200">
          <div class="p-4 border-b border-secondary-200 flex items-center justify-between">
            <h3 class="font-semibold text-secondary-900">Upload Queue</h3>
            <div class="flex gap-2">
              @if (hasCompleted()) {
                <button
                  (click)="clearCompleted()"
                  class="px-3 py-1.5 text-sm text-secondary-600 hover:text-secondary-800"
                >
                  Clear Completed
                </button>
              }
              @if (hasPending()) {
                <button
                  (click)="uploadAll()"
                  [disabled]="isUploading()"
                  class="px-4 py-1.5 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 disabled:opacity-50 flex items-center gap-2"
                >
                  @if (isUploading()) {
                    <fa-icon [icon]="faSpinner" class="animate-spin"></fa-icon>
                  }
                  Upload All
                </button>
              }
            </div>
          </div>
          <div class="divide-y divide-secondary-200">
            @for (item of uploadQueue(); track item.file.name; let i = $index) {
              <div class="p-4 flex items-center gap-4">
                <!-- File Icon -->
                <div
                  class="w-10 h-10 rounded-lg flex items-center justify-center"
                  [class]="getStatusBgClass(item.status)"
                >
                  @switch (item.status) {
                    @case ('success') {
                      <fa-icon [icon]="faCheckCircle" class="text-green-600"></fa-icon>
                    }
                    @case ('error') {
                      <fa-icon [icon]="faExclamationCircle" class="text-red-600"></fa-icon>
                    }
                    @case ('uploading') {
                      <fa-icon [icon]="faSpinner" class="text-primary-600 animate-spin"></fa-icon>
                    }
                    @default {
                      <fa-icon [icon]="faFile" class="text-secondary-500"></fa-icon>
                    }
                  }
                </div>

                <!-- File Info -->
                <div class="flex-1 min-w-0">
                  <p class="font-medium text-secondary-900 truncate">{{ item.file.name }}</p>
                  <p class="text-sm text-secondary-500">
                    {{ formatSize(item.file.size) }} &bull; {{ item.pkgType }}
                    @if (item.message) {
                      &bull; <span [class]="item.status === 'error' ? 'text-red-600' : 'text-green-600'">{{ item.message }}</span>
                    }
                  </p>
                </div>

                <!-- Progress / Actions -->
                <div class="flex items-center gap-3">
                  @if (item.status === 'uploading') {
                    <div class="w-24 h-2 bg-secondary-200 rounded-full overflow-hidden">
                      <div
                        class="h-full bg-primary-500 transition-all"
                        [style.width.%]="item.progress"
                      ></div>
                    </div>
                    <span class="text-sm text-secondary-500 w-12">{{ item.progress }}%</span>
                  } @else if (item.status === 'pending') {
                    <button
                      (click)="removeFromQueue(i)"
                      class="p-2 text-secondary-400 hover:text-red-500"
                    >
                      <fa-icon [icon]="faTimes"></fa-icon>
                    </button>
                  }
                </div>
              </div>
            }
          </div>
        </div>
      }
    </div>
  `,
})
export class UploadComponent {
  private apiService = inject(ApiService);

  faUpload = faUpload;
  faFile = faFile;
  faCheckCircle = faCheckCircle;
  faExclamationCircle = faExclamationCircle;
  faTimes = faTimes;
  faSpinner = faSpinner;

  selectedType = 'deb';
  isDragging = signal(false);
  uploadQueue = signal<UploadFile[]>([]);
  isUploading = signal(false);

  acceptedExtensions(): string {
    const map: Record<string, string> = {
      deb: '.deb',
      rpm: '.rpm',
      arch: '.pkg.tar.zst,.pkg.tar.xz,.pkg.tar.gz',
      alpine: '.apk',
    };
    return map[this.selectedType] || '*';
  }

  onDragOver(event: DragEvent) {
    event.preventDefault();
    event.stopPropagation();
    this.isDragging.set(true);
  }

  onDragLeave(event: DragEvent) {
    event.preventDefault();
    event.stopPropagation();
    this.isDragging.set(false);
  }

  onDrop(event: DragEvent) {
    event.preventDefault();
    event.stopPropagation();
    this.isDragging.set(false);

    const files = event.dataTransfer?.files;
    if (files) {
      this.addFiles(Array.from(files));
    }
  }

  onFileSelect(event: Event) {
    const input = event.target as HTMLInputElement;
    if (input.files) {
      this.addFiles(Array.from(input.files));
      input.value = '';
    }
  }

  addFiles(files: File[]) {
    const newItems: UploadFile[] = files.map((file) => ({
      file,
      progress: 0,
      status: 'pending' as const,
      pkgType: this.detectPackageType(file.name),
    }));

    this.uploadQueue.update((queue) => [...queue, ...newItems]);
  }

  detectPackageType(filename: string): string {
    if (filename.endsWith('.deb')) return 'deb';
    if (filename.endsWith('.rpm')) return 'rpm';
    if (filename.includes('.pkg.tar')) return 'arch';
    if (filename.endsWith('.apk')) return 'alpine';
    return this.selectedType;
  }

  removeFromQueue(index: number) {
    this.uploadQueue.update((queue) => queue.filter((_, i) => i !== index));
  }

  hasPending(): boolean {
    return this.uploadQueue().some((item) => item.status === 'pending');
  }

  hasCompleted(): boolean {
    return this.uploadQueue().some((item) => item.status === 'success' || item.status === 'error');
  }

  clearCompleted() {
    this.uploadQueue.update((queue) =>
      queue.filter((item) => item.status !== 'success' && item.status !== 'error')
    );
  }

  async uploadAll() {
    this.isUploading.set(true);
    const queue = this.uploadQueue();

    for (let i = 0; i < queue.length; i++) {
      const item = queue[i];
      if (item.status !== 'pending') continue;

      // Update status to uploading
      this.uploadQueue.update((q) => {
        q[i] = { ...q[i], status: 'uploading', progress: 0 };
        return [...q];
      });

      try {
        // Simulate progress (actual progress would require XMLHttpRequest)
        for (let p = 0; p <= 90; p += 10) {
          await new Promise((r) => setTimeout(r, 100));
          this.uploadQueue.update((q) => {
            q[i] = { ...q[i], progress: p };
            return [...q];
          });
        }

        await this.apiService.uploadPackage(item.pkgType, item.file).toPromise();

        this.uploadQueue.update((q) => {
          q[i] = { ...q[i], status: 'success', progress: 100, message: 'Uploaded successfully' };
          return [...q];
        });
      } catch (error: any) {
        this.uploadQueue.update((q) => {
          q[i] = {
            ...q[i],
            status: 'error',
            progress: 0,
            message: error?.error?.message || 'Upload failed',
          };
          return [...q];
        });
      }
    }

    this.isUploading.set(false);
  }

  formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  getStatusBgClass(status: string): string {
    switch (status) {
      case 'success':
        return 'bg-green-100';
      case 'error':
        return 'bg-red-100';
      case 'uploading':
        return 'bg-primary-100';
      default:
        return 'bg-secondary-100';
    }
  }
}
