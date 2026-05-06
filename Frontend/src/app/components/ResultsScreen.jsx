import { Fragment, jsx, jsxs } from "react/jsx-runtime";
import { useMemo, useState } from "react";
import { motion } from "motion/react";
import {
  Shield,
  Activity,
  Download,
  CheckCircle,
  Filter
} from "lucide-react";
import { ThreatTable } from "./ThreatTable";
import { ThreatCharts } from "./ThreatCharts";
import { RaspMonitoring } from "./RaspMonitoring";
import {
  getFilteredThreatData,
  getStatsCards,
  getThreatStats,
  THREAT_LEVEL_OPTIONS
} from "../lib/threats";
import { Button } from "./ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from "./ui/select";
import { DashboardPanel } from "./DashboardPanel";

// 1. IMPORT YOUR CUSTOM HOOK
import { useThreatAlerts } from "../../hooks/useThreatAlerts";
import { useRaspData } from "../../hooks/useRaspData";

function ResultsScreen({
  onNewScan,
  isRealTimeCapture,
  onToggleRealTime
}) {
  const [filterLevel, setFilterLevel] = useState("all");
  const [activeTab, setActiveTab] = useState("overview"); // "overview" or "rasp"
  
  // 2. FETCH LIVE DATA FROM YOUR FASTAPI BACKEND
  const { alerts: realThreatData, isLoading: isThreatsLoading } = useThreatAlerts(isRealTimeCapture);
  const { syscalls: raspData, isLoading: isRaspLoading } = useRaspData(activeTab === "rasp");

  const isLoading = activeTab === "overview" ? isThreatsLoading : isRaspLoading;

  // 3. COMPUTE STATS DYNAMICALLY BASED ON THE LIVE DATA
  const filteredData = useMemo(
    () => getFilteredThreatData(realThreatData, filterLevel),
    [filterLevel, realThreatData]
  );
  
  const stats = useMemo(() => getThreatStats(realThreatData), [realThreatData]);
  const statCards = useMemo(() => getStatsCards(realThreatData), [realThreatData]);

  // 4. SHOW A CLEAN LOADING STATE WHILE WAITING FOR FASTAPI
  if (isLoading) {
    return (
      <div className="flex size-full items-center justify-center">
        <p style={{ color: "#00d9ff", fontSize: "1.2rem", fontFamily: "monospace" }}>
          Scanning live network traffic...
        </p>
      </div>
    );
  }

  return /* @__PURE__ */ jsx("div", { className: "size-full overflow-y-auto px-6 py-8", children: /* @__PURE__ */ jsxs("div", { className: "max-w-[1600px] mx-auto", children: [
    /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: { opacity: 0, y: -20 },
        animate: { opacity: 1, y: 0 },
        className: "mb-8",
        children: [
          /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between mb-6", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4", children: [
              /* @__PURE__ */ jsx(Shield, { className: "w-10 h-10", style: { color: "#00d9ff" } }),
              /* @__PURE__ */ jsxs("div", { children: [
                /* @__PURE__ */ jsx("h1", { className: "text-3xl", style: { color: "#e8edf4" }, children: "Threat Detection System" }),
                /* @__PURE__ */ jsx("p", { style: { color: "#8b92a8" }, children: "Real-time vulnerability analysis" })
              ] })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ jsxs(
                Button,
                {
                  onClick: () => onToggleRealTime(!isRealTimeCapture),
                  className: "flex items-center gap-2 px-4 py-2 rounded-lg transition-all",
                  style: {
                    backgroundColor: isRealTimeCapture ? "#00ff8822" : "#1a1f2e",
                    border: `1px solid ${isRealTimeCapture ? "#00ff88" : "#1e2738"}`,
                    color: isRealTimeCapture ? "#00ff88" : "#8b92a8"
                  },
                  variant: "ghost",
                  children: [
                    /* @__PURE__ */ jsx(Activity, { className: "w-4 h-4" }),
                    isRealTimeCapture ? "Real-time Active" : "Real-time"
                  ]
                }
              ),
              /* @__PURE__ */ jsx(
                Button,
                {
                  onClick: onNewScan,
                  className: "px-6 py-2 rounded-lg transition-all",
                  style: {
                    backgroundColor: "#00d9ff",
                    color: "#0a0e1a"
                  },
                  children: "New Scan"
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ jsxs(
            motion.div,
            {
              initial: { opacity: 0, scale: 0.95 },
              animate: { opacity: 1, scale: 1 },
              transition: { delay: 0.2 },
              className: "px-6 py-4 rounded-lg border flex items-center gap-3",
              style: {
                backgroundColor: "#00ff8811",
                borderColor: "#00ff88"
              },
              children: [
                /* @__PURE__ */ jsx(CheckCircle, { className: "w-5 h-5", style: { color: "#00ff88" } }),
                /* @__PURE__ */ jsxs("span", { style: { color: "#00ff88" }, children: [
                  "Active Monitoring \u2014 ",
                  stats.threats,
                  " threats detected"
                ] })
              ]
            }
          )
        ]
      }
    ),

    /* @__PURE__ */ jsxs("div", {
      className: "flex items-center gap-1 mb-8 p-1 rounded-xl bg-[#0f1420] border border-[#1e2738] w-fit",
      children: [
        /* @__PURE__ */ jsx("button", {
          onClick: () => setActiveTab("overview"),
          className: `px-6 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === "overview" ? "bg-[#00d9ff15] text-[#00d9ff] shadow-[0_0_15px_rgba(0,217,255,0.1)]" : "text-[#8b92a8] hover:text-[#e8edf4]"}`,
          children: "Threat Overview"
        }),
        /* @__PURE__ */ jsxs("button", {
          onClick: () => setActiveTab("rasp"),
          className: `px-6 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${activeTab === "rasp" ? "bg-[#00d9ff15] text-[#00d9ff] shadow-[0_0_15px_rgba(0,217,255,0.1)]" : "text-[#8b92a8] hover:text-[#e8edf4]"}`,
          children: [
            /* @__PURE__ */ jsx(Activity, { className: "w-4 h-4" }),
            "RASP Live Monitoring"
          ]
        })
      ]
    }),

    activeTab === "overview" ? /* @__PURE__ */ jsx(Fragment, {
       children: [
         /* @__PURE__ */ jsx(
           motion.div,
           {
             initial: { opacity: 0, y: 20 },
             animate: { opacity: 1, y: 0 },
             transition: { delay: 0.3 },
             className: "grid grid-cols-4 gap-4 mb-8",
             children: statCards.map((stat, index) => /* @__PURE__ */ jsx(
               motion.div,
               {
                 initial: { opacity: 0, scale: 0.9 },
                 animate: { opacity: 1, scale: 1 },
                 transition: { delay: 0.4 + index * 0.1 },
                 children: /* @__PURE__ */ jsxs(DashboardPanel, { className: "p-6", children: [
                   /* @__PURE__ */ jsx("div", { className: "mb-3 flex items-start justify-between", children: /* @__PURE__ */ jsx(stat.icon, { className: "h-5 w-5", style: { color: stat.color } }) }),
                   /* @__PURE__ */ jsx("div", { className: "mb-1 text-3xl", style: { color: stat.color }, children: stat.value }),
                   /* @__PURE__ */ jsx("div", { className: "text-sm", style: { color: "#8b92a8" }, children: stat.label })
                 ] })
               },
               stat.label
             ))
           },
           "stats-grid"
         ),
         /* @__PURE__ */ jsx(
           motion.div,
           {
             initial: { opacity: 0, y: 20 },
             animate: { opacity: 1, y: 0 },
             transition: { delay: 0.7 },
             className: "mb-8",
             children: /* @__PURE__ */ jsx(ThreatCharts, { data: realThreatData })
           },
           "charts-grid"
         ),
         /* @__PURE__ */ jsxs(
           motion.div,
           {
             initial: { opacity: 0, y: 20 },
             animate: { opacity: 1, y: 0 },
             transition: { delay: 0.9 },
             children: [
               /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between mb-4", children: [
                 /* @__PURE__ */ jsx("h2", { className: "text-xl", style: { color: "#e8edf4" }, children: "Detected Vulnerabilities" }),
                 /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
                   /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
                     /* @__PURE__ */ jsx(Filter, { className: "w-4 h-4", style: { color: "#8b92a8" } }),
                     /* @__PURE__ */ jsxs(
                       Select,
                       {
                         value: filterLevel,
                         onValueChange: (value) => setFilterLevel(value),
                         children: [
                           /* @__PURE__ */ jsx(
                             SelectTrigger,
                             {
                               className: "w-[180px] rounded-lg border",
                               style: {
                                 backgroundColor: "#0f1420",
                                 borderColor: "#1e2738",
                                 color: "#e8edf4"
                               },
                               children: /* @__PURE__ */ jsx(SelectValue, { placeholder: "All Levels" })
                             }
                           ),
                           /* @__PURE__ */ jsx(SelectContent, { children: THREAT_LEVEL_OPTIONS.map((option) => /* @__PURE__ */ jsx(SelectItem, { value: option.value, children: option.label }, option.value)) })
                         ]
                       }
                     )
                   ] }),
                   /* @__PURE__ */ jsxs(
                     Button,
                     {
                       className: "flex items-center gap-2 px-4 py-2 rounded-lg border transition-all hover:border-[#00d9ff]",
                       style: {
                         backgroundColor: "#0f1420",
                         borderColor: "#1e2738",
                         color: "#8b92a8"
                       },
                       variant: "ghost",
                       children: [
                         /* @__PURE__ */ jsx(Download, { className: "w-4 h-4" }),
                         "Export CSV"
                       ]
                     }
                   )
                 ] })
               ] }),
               /* @__PURE__ */ jsx(ThreatTable, { data: filteredData })
             ]
           },
           "table-grid"
         )
       ]
     }) : /* @__PURE__ */ jsx(
      motion.div,
      {
        initial: { opacity: 0, y: 20 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.4 },
        children: /* @__PURE__ */ jsx(RaspMonitoring, { syscallData: raspData })
      },
      "rasp-grid"
    )
  ] }) });
}
export {
  ResultsScreen
};