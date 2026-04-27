// src/api/threatRoutes.js
import { API_BASE_URL } from "./config";
import { mapBackendAlertsToFrontend } from "../app/lib/threats";

export const threatAPI = {
  getAlerts: async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/alerts`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      
      // Pass the raw Python JSON through the mapper we will build in Step 3
      // We use .reverse() so the newest Zero-Day attacks appear at the top of your UI table
      const formattedData = mapBackendAlertsToFrontend(data.alerts);
      return formattedData.reverse(); 
      
    } catch (error) {
      console.error("Failed to fetch threat alerts:", error);
      // Return an empty array on failure so the dashboard UI remains stable
      return []; 
    }
  }
};