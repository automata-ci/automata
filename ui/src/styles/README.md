# UI stylesheet architecture

`../styles.css` is the production application entrypoint. It declares the
cascade order and imports every production module into one of these layers:

1. `reset` removes browser defaults that would destabilize the layout.
2. `tokens` owns reusable fonts, dimensions, and all palette values.
3. `base` contains the icon font and accessibility foundations.
4. `layout` owns containers, page grids, shell geometry, and navigation flow.
5. `components` owns reusable visual skins such as controls, panels, and status.
6. `pages` owns rules that only make sense for one page family.
7. `conditions` owns responsive, input-mode, reduced-motion, and forced-color overrides.

Add a component to the narrowest existing module, or add one focused file and
import it in the matching layer. Keep raw colors in `foundations/tokens.css`;
component files should consume semantic custom properties. Keep breakpoints in
`conditions/responsive.css` so structural overrides remain visible in one
place. Prefer container queries there for page content whose available width is
controlled by the navigation column; reserve viewport queries for shell and
navigation changes. Do not add rules to `styles.css`, introduce a
general-purpose utility for a one-off layout, or move page behavior into CSS.

The browser demo imports `pages/preview.css` directly from `../preview.tsx`,
after the production entrypoint. That module wraps its rules in `@layer pages`
so it participates in the declared cascade without shipping preview-only
selectors in the production client. Preview-only wrappers belong there;
reusable component states belong in the appropriate `components` module.
