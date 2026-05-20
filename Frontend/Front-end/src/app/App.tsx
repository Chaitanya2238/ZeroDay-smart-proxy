import { useEffect, useState } from "react";
import { InputScreen } from "./components/InputScreen";
import { ScanningScreen } from "./components/ScanningScreen";
import { ResultsScreen } from "./components/ResultsScreen";
import type { ScanInput, ThreatData } from "./lib/threats";

export type Screen = "input" | "scanning" | "results";

export default function App() {
  const [currentScreen, setCurrentScreen] = useState<Screen>("input");
  const [isRealTimeCapture, setIsRealTimeCapture] = useState(false);

  const [scanResults, setScanResults] = useState<ThreatData[]>([]);

  const fetchAlertHistory = async () => {
    try {
      const response = await fetch("http://localhost:8000/api/alerts", { cache: "no-store" });
      if (response.ok) {
        const data = await response.json();
        if (data.alerts && Array.isArray(data.alerts)) {
          const mappedHistory = data.alerts.map((alert: any) => {
            const severity = alert.severity;
            return {
              id: `LOG-${alert.alert_id}`,
              packetName: (alert.original_request?.path || "Unknown").substring(0, 30),
              protocol: alert.original_request?.method || "MANUAL",
              sourceIp: alert.original_request?.client_ip || "127.0.0.1",
              destIp: "Target Proxy",
              threatType: alert.threat_type || "UNKNOWN",
              threatLevel: severity >= 8 ? "critical" : severity >= 5 ? "high" : severity >= 3 ? "medium" : severity >= 1 ? "low" : "safe",
              confidence: Math.round((alert.confidence || 0) * 100),
              status: alert.recommended_action === "block" ? "blocked" : alert.recommended_action === "monitor" ? "monitored" : "allowed",
              prevention: alert.recommended_action === "block" ? "block" : alert.recommended_action === "monitor" ? "alert" : "allow",
              timestamp: (alert.timestamp || "").replace("T", " ").substring(0, 19),
            };
          });
          // Sort so newest is first
          setScanResults(mappedHistory.reverse());
        }
      }
    } catch (err) {
      console.error("Failed to fetch alert history:", err);
    }
  };

  useEffect(() => {
    fetchAlertHistory();
  }, []);

  useEffect(() => {
    let intervalId: number | undefined;
    if (isRealTimeCapture) {
      intervalId = window.setInterval(() => {
        fetchAlertHistory();
      }, 2000);
    }
    return () => {
      if (intervalId) {
        window.clearInterval(intervalId);
      }
    };
  }, [isRealTimeCapture]);

  const handleStartScan = async (input: ScanInput) => {
    setCurrentScreen("scanning");
    
    try {
      let content = input.query;
      let type = "packet";
      
      // Basic check if it's a URL
      if (input.query.startsWith("http") || input.query.includes("://") || input.query.includes(".com")) {
        type = "website";
      }

      if (input.file) {
        content = await input.file.text();
      }

      const response = await fetch("http://localhost:8000/api/analyze-manual", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, content, target: input.query }),
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();
      
      
      // After scan completes, fetch the full updated history!
      await fetchAlertHistory();
      
    } catch (err) {
      console.error("Scan failed:", err);
      // Fallback empty result on error
      setScanResults([]);
    } finally {
      setCurrentScreen("results");
    }
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
          resultsData={scanResults}
        />
      )}
    </div>
  );
}
