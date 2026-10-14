import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { ApplicationConfig, inject, provideAppInitializer, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideAnimations } from '@angular/platform-browser/animations';
import { provideRouter, TitleStrategy, withComponentInputBinding } from '@angular/router';
import { ClrCommonStringsService } from '@clr/angular';
import { routes } from './app.routes';
import { apiInterceptor } from './core/api';
import { clarityStrings } from './core/clarity-strings';
import { AppTitle } from './core/title';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes, withComponentInputBinding()),
    provideHttpClient(withInterceptors([apiInterceptor])),
    provideAnimations(),
    { provide: TitleStrategy, useClass: AppTitle },
    // Translated text for Clarity's built-in component labels.
    provideAppInitializer(() => inject(ClrCommonStringsService).localize(clarityStrings())),
  ],
};
