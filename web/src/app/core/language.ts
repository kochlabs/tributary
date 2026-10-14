/** The language's own name for itself, e.g. "Deutsch" for de, "English (United States)" for en-US. */
export function languageName(code: string): string {
  try {
    const name = new Intl.DisplayNames([code], { type: 'language', languageDisplay: 'standard' }).of(code);
    if (name) return name.charAt(0).toLocaleUpperCase(code) + name.slice(1);
  } catch {
    // Unknown to this browser: show the code.
  }
  return code;
}

/** Remembers the chosen UI language for a year; the server reads it. */
export function setLanguageCookie(code: string) {
  document.cookie = `nfa_lang=${encodeURIComponent(code)}; path=/; max-age=31536000; SameSite=Strict${location.protocol === 'https:' ? '; Secure' : ''}`;
}
