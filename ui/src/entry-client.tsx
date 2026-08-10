import { hydrateRoot } from "react-dom/client";
import { HtmlDocument } from "./Document";
import { readRenderRequest } from "./serialization";
import "./styles.css";

const request = readRenderRequest(document);

hydrateRoot(document, <HtmlDocument request={request} />);
