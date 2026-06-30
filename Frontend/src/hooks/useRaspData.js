import { useEffect, useState, useRef } from "react";
import { API_BASE_URL } from "../api/config";

/**
 * Custom hook for live RASP (Runtime Application Self-Protection) data
 * Fetches REAL-TIME data from the backend
 */
export function useRaspData(isActive = false) {
  const [syscalls, setSyscalls] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const intervalRef = useRef(null);

  useEffect(() => {
    if (!isActive) {
      if (intervalRef.current) clearInterval(intervalRef.current);
      return;
    }

    setIsLoading(true);
    
    const fetchInitialData = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/rasp`);
        const data = await response.json();
        setSyscalls(data);
      } catch (error) {
        console.error("Error fetching initial RASP data:", error);
      } finally {
        setIsLoading(false);
      }
    };
    
    fetchInitialData();

    intervalRef.current = setInterval(async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/rasp/latest`);
        const data = await response.json();
        if (data && data.id) {
          setSyscalls(prev => {
            const updated = [...prev, data];
            return updated.slice(-50);
          });
        }
      } catch (error) {
        console.error("Error fetching latest RASP data:", error);
      }
    }, 500);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isActive]);

  return { syscalls, isLoading };
}
