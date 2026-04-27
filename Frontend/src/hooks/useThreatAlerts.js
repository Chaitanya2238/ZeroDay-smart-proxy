// src/hooks/useThreatAlerts.js
import { useState, useEffect } from "react";
import { threatAPI } from "../api/threatRoutes";

export function useThreatAlerts(isRealTimeActive) {
  const [alerts, setAlerts] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  const fetchLatestThreats = async () => {
    // Calls the API route we built in Step 2
    const latestData = await threatAPI.getAlerts();
    setAlerts(latestData);
    setIsLoading(false);
  };

  useEffect(() => {
    // 1. Fetch immediately when the dashboard loads
    fetchLatestThreats();

    // 2. If the user clicks "Enable Real-time", start polling every 2 seconds
    let pollInterval;
    if (isRealTimeActive) {
      pollInterval = setInterval(() => {
        fetchLatestThreats();
      }, 2000);
    }

    // 3. Cleanup to prevent memory leaks when the component unmounts
    return () => {
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [isRealTimeActive]);

  return { alerts, isLoading, refreshAlerts: fetchLatestThreats };
}