import { jsx, jsxs } from "react/jsx-runtime";
import { useEffect, useState } from "react";
import { InputScreen } from "./components/InputScreen";
import { ScanningScreen } from "./components/ScanningScreen";
import { ResultsScreen } from "./components/ResultsScreen";
function App() {
  const [currentScreen, setCurrentScreen] = useState("input");
  const [isRealTimeCapture, setIsRealTimeCapture] = useState(false);
  useEffect(() => {
    if (currentScreen !== "scanning") {
      return void 0;
    }
    const timer = window.setTimeout(() => {
      setCurrentScreen("results");
    }, 4e3);
    return () => {
      window.clearTimeout(timer);
    };
  }, [currentScreen]);
  const handleStartScan = (_input) => {
    setCurrentScreen("scanning");
  };
  const handleNewScan = () => {
    setCurrentScreen("input");
    setIsRealTimeCapture(false);
  };
  const handleToggleRealTime = (enabled) => {
    setIsRealTimeCapture(enabled);
    if (enabled) {
      setCurrentScreen("results");
    }
  };
  return /* @__PURE__ */ jsxs("div", { className: "size-full bg-background dark", children: [
    currentScreen === "input" && /* @__PURE__ */ jsx(
      InputScreen,
      {
        onStartScan: handleStartScan,
        onToggleRealTime: handleToggleRealTime,
        isRealTimeCapture
      }
    ),
    currentScreen === "scanning" && /* @__PURE__ */ jsx(ScanningScreen, {}),
    currentScreen === "results" && /* @__PURE__ */ jsx(
      ResultsScreen,
      {
        onNewScan: handleNewScan,
        isRealTimeCapture,
        onToggleRealTime: handleToggleRealTime
      }
    )
  ] });
}
export {
  App as default
};
