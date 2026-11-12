import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import "./top-menu/top-menu.css";
import "./styles/standalone-ui.css";
import "./app.css";

createRoot(document.getElementById("root")).render(<App />);
