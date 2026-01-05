import { Component, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { IconDefinition } from '@fortawesome/fontawesome-svg-core';

@Component({
  selector: 'app-stat-card',
  standalone: true,
  imports: [RouterLink, FontAwesomeModule],
  template: `
    <a
      [routerLink]="link()"
      class="block bg-white rounded-lg shadow-sm border border-secondary-200 p-6 hover:shadow-md hover:border-primary-300 transition-all group"
    >
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm font-medium text-secondary-500">{{ label() }}</p>
          <p class="text-3xl font-bold text-secondary-900 mt-1">{{ value() }}</p>
          @if (subtitle()) {
            <p class="text-xs text-secondary-400 mt-1">{{ subtitle() }}</p>
          }
        </div>
        <div
          class="w-12 h-12 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform"
          [class]="iconBgClass()"
        >
          <fa-icon [icon]="icon()" [class]="iconClass()" class="text-xl"></fa-icon>
        </div>
      </div>
    </a>
  `,
})
export class StatCardComponent {
  label = input.required<string>();
  value = input.required<number | string>();
  icon = input.required<IconDefinition>();
  link = input.required<string>();
  subtitle = input<string>();
  iconBgClass = input<string>('bg-primary-100');
  iconClass = input<string>('text-primary-600');
}
