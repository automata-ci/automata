import { hydrateRoot } from "react-dom/client";
import { HtmlDocument } from "./Document";
import { installViewerMenuDismissal } from "./enhancements/viewerMenu";
import { readRenderRequest } from "./serialization";
import "./styles.css";

const request = readRenderRequest(document);

installViewerMenuDismissal(document);
hydrateRoot(document, <HtmlDocument request={request} />);
