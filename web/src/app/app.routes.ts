import { Routes } from '@angular/router';
import { adminGuard, authGuard } from './core/auth';
import { Shell } from './shell';
import { Login } from './pages/login';

export const routes: Routes = [
  { path: 'login', component: Login, title: $localize`:@@login.title:Sign in` },
  {
    path: '',
    component: Shell,
    canActivate: [authGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      { path: 'dashboard', loadComponent: () => import('./pages/dashboard').then((m) => m.Dashboard), title: $localize`:@@nav.dashboard:Dashboard` },
      { path: 'explorer', loadComponent: () => import('./pages/explorer').then((m) => m.Explorer), title: $localize`:@@nav.explorer:Traffic Explorer` },
      { path: 'flows', loadComponent: () => import('./pages/flows').then((m) => m.Flows), title: $localize`:@@nav.flows:Flow Search` },
      { path: 'devices', loadComponent: () => import('./pages/devices').then((m) => m.Devices), title: $localize`:@@nav.devices:Devices` },
      { path: 'exporters', loadComponent: () => import('./pages/exporters').then((m) => m.Exporters), title: $localize`:@@nav.exporters:Exporters` },
      { path: 'exporters/:addr', loadComponent: () => import('./pages/exporter-detail').then((m) => m.ExporterDetail), title: $localize`:@@nav.exporter:Exporter` },
      { path: 'reports', loadComponent: () => import('./pages/reports').then((m) => m.Reports), title: $localize`:@@nav.reports:Reports` },
      { path: 'security/detections', loadComponent: () => import('./pages/detections').then((m) => m.Detections), title: $localize`:@@nav.detections:Detections` },
      { path: 'security/threat-feeds', canActivate: [adminGuard], loadComponent: () => import('./pages/threat-feeds').then((m) => m.ThreatFeeds), title: $localize`:@@nav.threatFeeds:Threat Feeds` },
      { path: 'system', loadComponent: () => import('./pages/system').then((m) => m.System), title: $localize`:@@nav.system:System Health` },
      {
        path: 'admin',
        canActivate: [adminGuard],
        children: [
          { path: 'settings', loadComponent: () => import('./pages/settings').then((m) => m.SettingsPage), title: $localize`:@@nav.settings:Settings` },
          { path: 'users', loadComponent: () => import('./pages/users').then((m) => m.Users), title: $localize`:@@nav.users:Users` },
          { path: 'local-networks', loadComponent: () => import('./pages/local-networks').then((m) => m.LocalNetworks), title: $localize`:@@nav.localNetworks:Local Networks` },
          { path: 'enrichment', loadComponent: () => import('./pages/enrichment').then((m) => m.EnrichmentPage), title: $localize`:@@nav.enrichment:Enrichment` },
          { path: 'email', loadComponent: () => import('./pages/email').then((m) => m.EmailPage), title: $localize`:@@nav.email:Email` },
          { path: 'data-sources', redirectTo: 'enrichment' },
          { path: 'backup', loadComponent: () => import('./pages/backup').then((m) => m.Backup), title: $localize`:@@nav.backup:Backup & Restore` },
          { path: 'certificates', loadComponent: () => import('./pages/certificates').then((m) => m.Certificates), title: $localize`:@@nav.certificates:Certificates` },
          { path: 'identity-sources', loadComponent: () => import('./pages/identity-sources').then((m) => m.IdentitySources), title: $localize`:@@nav.identitySources:Identity Sources` },
          { path: 'updates', loadComponent: () => import('./pages/updates').then((m) => m.Updates), title: $localize`:@@nav.updates:Updates` },
          { path: 'time', loadComponent: () => import('./pages/time').then((m) => m.Time), title: $localize`:@@nav.time:Time` },
          { path: 'services', loadComponent: () => import('./pages/services').then((m) => m.Services), title: $localize`:@@nav.services:Services` },
          { path: 'api-tokens', loadComponent: () => import('./pages/api-tokens').then((m) => m.ApiTokens), title: $localize`:@@nav.apiTokens:API Tokens` },
          { path: 'audit', loadComponent: () => import('./pages/audit').then((m) => m.Audit), title: $localize`:@@nav.audit:Audit Log` },
        ],
      },
      { path: '**', redirectTo: 'dashboard' },
    ],
  },
];
