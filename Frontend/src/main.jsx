import { jsx } from "react/jsx-runtime";
import { createRoot } from "react-dom/client";
import App from "./app/App.jsx";
import "./styles/index.css";
createRoot(document.getElementById("root")).render(/* @__PURE__ */ jsx(App, {}));
