import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { registerIcons } from './core/icons';
import { Theme } from './core/util';

registerIcons();

@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  template: '<router-outlet />',
})
export class App {
  // Instantiated eagerly so the saved theme is applied before first paint.
  private theme = inject(Theme);
}
