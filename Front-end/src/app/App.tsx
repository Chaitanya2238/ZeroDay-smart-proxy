import { useEffect, useState } from "react";
import { InputScreen } from "./components/InputScreen";
import { ScanningScreen } from "./components/ScanningScreen";
import { ResultsScreen } from "./components/ResultsScreen";
import type { ScanInput } from "./lib/threats";

export type Screen = "input" | "scanning" | "results";

export default function App() {
  const [currentScreen, setCurrentScreen] = useState<Screen>("input");
  const [isRealTimeCapture, setIsRealTimeCapture] = useState(false);

  useEffect(() => {
    if (currentScreen !== "scanning") {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      setCurrentScreen("results");
    }, 4000);

    return () => {
      window.clearTimeout(timer);
    };
  }, [currentScreen]);

  const handleStartScan = (_input: ScanInput) => {
    setCurrentScreen("scanning");
  };

  const handleNewScan = () => {
    setCurrentScreen("input");
    setIsRealTimeCapture(false);
  };

  const handleToggleRealTime = (enabled: boolean) => {
    setIsRealTimeCapture(enabled);
    if (enabled) {
      setCurrentScreen("results");
    }
  };

  return (
    <div className="size-full bg-background dark">
      {currentScreen === "input" && (
        <InputScreen
          onStartScan={handleStartScan}
          onToggleRealTime={handleToggleRealTime}
          isRealTimeCapture={isRealTimeCapture}
        />
      )}
      {currentScreen === "scanning" && <ScanningScreen />}
      {currentScreen === "results" && (
        <ResultsScreen
          onNewScan={handleNewScan}
          isRealTimeCapture={isRealTimeCapture}
          onToggleRealTime={handleToggleRealTime}
        />
      )}
    </div>
  );
}
