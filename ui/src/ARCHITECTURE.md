# React presentation architecture

Automata keeps rendering independently testable from browser behavior and host
protocols. A component does not need ceremonial layers when it is already a pure
function of props, but stateful features follow one dependency direction:

```text
page container -> hook/service + presenter -> view -> shared components
```

## Boundaries

- `pages/` connects validated host models and feature behavior. Page containers
  stay thin and retain the stable exports used by `App`.
- `views/` contains pure page and feature presentation. Views receive state,
  callbacks, links, and native form capabilities through props. They do not
  import hooks, services, validation, or transport controllers and do not read
  browser globals.
- `components/` contains reusable presentation. A small number of compatibility
  containers, such as `ThemeToggle`, connect a colocated view to a hook.
- `hooks/` owns React state, effects, DOM measurement, and browser lifecycle.
- `presenters/` performs deterministic model-to-view projection.
- `services/` owns transport protocols and has no React dependency.
- `viewModels/` defines the explicit contract between behavior and presentation.

Every presentation surface has a Storybook story. Stories use typed CSF,
production CSS, representative host-neutral fixtures, interaction callbacks,
and blocking accessibility checks. Vitest continues to cover presenters, hooks,
services, SSR, and hydration; the Storybook project runs stories in Chromium.

Native links and forms remain functional without JavaScript. Hooks enhance that
baseline but cannot replace host authorization, CSRF protection, validation, or
the immutable server-rendered model.
