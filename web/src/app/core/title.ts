import { inject, Injectable } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { RouterStateSnapshot, TitleStrategy } from '@angular/router';

@Injectable({ providedIn: 'root' })
export class AppTitle extends TitleStrategy {
  private title = inject(Title);
  override updateTitle(snapshot: RouterStateSnapshot) {
    const t = this.buildTitle(snapshot);
    this.title.setTitle(t ? `${t} · Tributary` : 'Tributary');
  }
}
