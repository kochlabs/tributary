import { computed, inject, Injectable, signal } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { Api, User } from './api';

@Injectable({ providedIn: 'root' })
export class Auth {
  private api = inject(Api);
  readonly user = signal<User | null>(null);
  readonly isAdmin = computed(() => this.user()?.role === 'admin');
  private checked = false;

  async ensure(): Promise<User | null> {
    if (this.checked) return this.user();
    try {
      this.user.set(await this.api.me());
    } catch {
      this.user.set(null);
    }
    this.checked = true;
    return this.user();
  }

  async login(username: string, password: string) {
    this.user.set(await this.api.login(username, password));
    this.checked = true;
  }

  async logout() {
    try {
      await this.api.logout();
    } finally {
      this.user.set(null);
    }
  }
}

export const authGuard: CanActivateFn = async (_route, state) => {
  const auth = inject(Auth);
  const router = inject(Router);
  if (await auth.ensure()) return true;
  return router.createUrlTree(['/login'], { queryParams: state.url !== '/' ? { next: state.url } : {} });
};

export const adminGuard: CanActivateFn = async () => {
  const auth = inject(Auth);
  const router = inject(Router);
  const u = await auth.ensure();
  return u?.role === 'admin' ? true : router.createUrlTree(['/dashboard']);
};
