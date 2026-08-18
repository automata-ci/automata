import { App } from "./App";
import { THEME_BOOTSTRAP_SCRIPT } from "./hooks/useThemePreference";
import type { RenderRequest } from "./models";
import { PAGE_MODEL_ELEMENT_ID, serializeForHtml } from "./serialization";

export interface HtmlDocumentProps {
  readonly request: RenderRequest;
}

export function HtmlDocument({ request }: HtmlDocumentProps) {
  const { page } = request;
  const { assets, cspNonce, locale } = request.host;

  return (
    <html lang={locale} suppressHydrationWarning>
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="description" content={page.shell.description} />
        <meta name="color-scheme" content="light dark" />
        <title>{page.shell.documentTitle}</title>
        <script
          nonce={cspNonce}
          dangerouslySetInnerHTML={{ __html: THEME_BOOTSTRAP_SCRIPT }}
        />
        {assets.stylesheets.map((href) => (
          <link rel="stylesheet" href={href} key={href} />
        ))}
      </head>
      <body>
        <App page={page} />
        <script
          id={PAGE_MODEL_ELEMENT_ID}
          type="application/json"
          nonce={cspNonce}
          dangerouslySetInnerHTML={{ __html: serializeForHtml(request) }}
        />
        <script type="module" src={assets.clientEntry} nonce={cspNonce} />
      </body>
    </html>
  );
}
