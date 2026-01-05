import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Package {
  name: string;
  version: string;
  architecture: string;
  package_type: string;
  filename: string;
  size: number;
}

export interface PackageListResponse {
  packages: Package[];
  total: number;
  page: number;
  per_page: number;
}

export interface HealthResponse {
  status: string;
  storage: string;
}

export interface RegistryStats {
  type: string;
  count: number;
  icon: string;
}

@Injectable({
  providedIn: 'root',
})
export class ApiService {
  private http = inject(HttpClient);
  private baseUrl = '/api/v1';

  // Health endpoints
  getHealth(): Observable<HealthResponse> {
    return this.http.get<HealthResponse>('/health');
  }

  getReadiness(): Observable<HealthResponse> {
    return this.http.get<HealthResponse>('/ready');
  }

  // Package endpoints
  listPackages(params?: {
    page?: number;
    per_page?: number;
    arch?: string;
  }): Observable<PackageListResponse> {
    let httpParams = new HttpParams();
    if (params?.page) httpParams = httpParams.set('page', params.page.toString());
    if (params?.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());
    if (params?.arch) httpParams = httpParams.set('arch', params.arch);

    return this.http.get<PackageListResponse>(`${this.baseUrl}/packages`, { params: httpParams });
  }

  listPackagesByType(
    pkgType: string,
    params?: { page?: number; per_page?: number; arch?: string }
  ): Observable<PackageListResponse> {
    let httpParams = new HttpParams();
    if (params?.page) httpParams = httpParams.set('page', params.page.toString());
    if (params?.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());
    if (params?.arch) httpParams = httpParams.set('arch', params.arch);

    return this.http.get<PackageListResponse>(`${this.baseUrl}/packages/${pkgType}`, {
      params: httpParams,
    });
  }

  deletePackage(pkgType: string, name: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/packages/${pkgType}/${name}`);
  }

  uploadPackage(pkgType: string, file: File): Observable<{ message: string; filename: string }> {
    const formData = new FormData();
    formData.append('file', file);
    return this.http.post<{ message: string; filename: string }>(
      `${this.baseUrl}/upload/${pkgType}`,
      formData
    );
  }

  rebuildRepo(pkgType: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.baseUrl}/repos/${pkgType}/rebuild`, {});
  }

  // Cargo endpoints
  listCrates(): Observable<{ crates: any[] }> {
    return this.http.get<{ crates: any[] }>('/cargo/api/v1/crates');
  }

  // npm endpoints
  listNpmPackages(): Observable<any> {
    return this.http.get<any>('/npm/-/all');
  }

  // Get setup script/config
  getSetupScript(type: string): Observable<string> {
    return this.http.get(`/setup/${type}`, { responseType: 'text' });
  }
}
