# Translating Tributary

The web interface is written in US English (`en-US`) and uses Angular's
built-in internationalization ([`@angular/localize`](https://angular.dev/guide/i18n)).
Every piece of interface text is marked in the source with a stable ID, and
`make i18n` extracts it into an [XLIFF 2.0](https://docs.oasis-open.org/xliff/xliff-core/v2.0/xliff-core-v2.0.html)
file that translation tools such as Weblate, Crowdin, Transifex, Poedit or
Lokalise can open directly.

Each language is compiled into its own copy of the interface. The appliance
serves the language a user picked in the user menu, otherwise the best match
for their browser's language, otherwise English. Dates and numbers follow the
browser's regional settings regardless of language.

## Adding a language

1. **Extract the current text** (also run this after changing interface text):

   ```bash
   make i18n
   ```

   This writes `web/src/locale/messages.xlf`, the English source. Don't edit it.

2. **Create the translation file** for your language by copying the source,
   using a [BCP 47 tag](https://www.w3.org/International/articles/language-tags/)
   such as `de`, `fr`, `pt-BR` or `zh-Hans`:

   ```bash
   cp web/src/locale/messages.xlf web/src/locale/messages.de.xlf
   ```

   Set `trgLang="de"` on the `<xliff>` element, then add a `<target>` after
   each `<source>` (or open the file in a translation tool, which does this for
   you).

3. **Register it** in `web/angular.json` under `projects.web.i18n.locales`,
   keeping `baseHref` at `/` so addresses stay the same in every language:

   ```json
   "locales": {
     "de": { "translation": "src/locale/messages.de.xlf", "baseHref": "/" }
   }
   ```

4. **Build and try it:**

   ```bash
   make web build
   ```

   The language appears in the user menu under **Language**. To preview it
   with live reload instead: `cd web && npx ng serve --configuration=development,de`
   after adding a matching `de` build configuration with `"localize": ["de"]`.

## What to keep in mind

- **Placeholders** such as `<ph name="INTERPOLATION"/>` stand for values filled
  in at runtime (counts, names, sizes). Keep every placeholder; you may move it.
- **Plurals** use ICU syntax: `{VAR_PLURAL, plural, =1 {…} other {…}}`. Add the
  categories your language needs (`few`, `many`, …); keep the variable name.
- **Clarity component text** (`clr.*` IDs: pagination, filters, alert pager…)
  contains placeholders in braces like `{COLUMN}` or `{COUNT}`. Keep them as
  they are; Clarity replaces them.
- **Missing translations** fall back to English, so a partial translation is
  usable. The build lists them as warnings.
- **IDs are stable.** When the English text of a message changes, its ID stays
  the same, so existing translations keep working; translation tools that track
  the source text flag them for review.

## What isn't translated yet

Error messages that come from the server (for example a failed validation) are
in English. Appliance notices shown in the banner above the header are
translated in the interface; any notice the interface doesn't know yet shows the
server's English text.
