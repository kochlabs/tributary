import { Routes } from '@angular/router';
import { adminGuard, authGuard } from './core/auth';
import { Shell } from './shell';
import { Login } from './pages/login';

export const routes: Routes = [
  { path: 'login', component: Login, title: 'Sign in' },
  {
    path: '',
    component: Shell,
    canActivate: [authGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      { path: 'dashboard', loadComponent: () => import('./pages/dashboard').then((m) => m.Dashboard), title: 'Dashboard' },
      { path: 'explorer', loadComponent: () => import('./pages/explorer').then((m) => m.Explorer), title: 'Traffic Explorer' },
      { path: 'flows', loadComponent: () => import('./pages/flows').then((m) => m.Flows), title: 'Flow Search' },
      { path: 'exporters', loadComponent: () => import('./pages/exporters').then((m) => m.Exporters), title: 'Exporters' },
      { path: 'exporters/:addr', loadComponent: () => import('./pages/exporter-detail').then((m) => m.ExporterDetail), title: 'Exporter' },
      { path: 'system', loadComponent: () => import('./pages/system').then((m) => m.System), title: 'System Health' },
      {
        path: 'admin',
        canActivate: [adminGuard],
        children: [
          { path: 'settings', loadComponent: () => import('./pages/settings').then((m) => m.SettingsPage), title: 'Settings' },
          { path: 'users', loadComponent: () => import('./pages/users').then((m) => m.Users), title: 'Users' },
          { path: 'certificates', loadComponent: () => import('./pages/certificates').then((m) => m.Certificates), title: 'Certificates' },
          { path: 'identity-sources', loadComponent: () => import('./pages/identity-sources').then((m) => m.IdentitySources), title: 'Identity Sources' },
          { path: 'updates', loadComponent: () => import('./pages/updates').then((m) => m.Updates), title: 'Updates' },
          { path: 'time', loadComponent: () => import('./pages/time').then((m) => m.Time), title: 'Time' },
          { path: 'services', loadComponent: () => import('./pages/services').then((m) => m.Services), title: 'Services' },
          { path: 'audit', loadComponent: () => import('./pages/audit').then((m) => m.Audit), title: 'Audit Log' },
        ],
      },
      { path: '**', redirectTo: 'dashboard' },
    ],
  },
];
