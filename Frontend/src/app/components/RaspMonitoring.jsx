import { jsx, jsxs } from "react/jsx-runtime";
import { useMemo } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area
} from "recharts";
import { DashboardPanel } from "./DashboardPanel";
import { Activity, ShieldAlert, Cpu } from "lucide-react";

/**
 * RASP Monitoring Component
 * Displays live system call activity and Markov Chain anomaly detection status
 */
export function RaspMonitoring({ syscallData = [] }) {
  // Mock data for the graph if no data is provided
  const chartData = useMemo(() => {
    if (syscallData.length > 0) {
      return syscallData.map((d, i) => ({
        index: i,
        time: d.timestamp.split('T')[1].split('.')[0],
        count: d.syscall_count || 1,
        probability: d.markov_probability || (Math.random() * 0.5 + 0.5),
        isAnomaly: d.is_anomaly || false
      }));
    }
    
    // Default mock data for visualization
    return Array.from({ length: 20 }).map((_, i) => ({
      index: i,
      time: `${12 + Math.floor(i/10)}:${(i%10)*6}:00`,
      count: Math.floor(Math.random() * 50) + 10,
      probability: Math.random() * 0.4 + 0.6,
      isAnomaly: Math.random() > 0.95
    }));
  }, [syscallData]);

  const recentSyscalls = useMemo(() => {
    if (syscallData.length > 0) {
      // Map backend data to frontend format
      return syscallData.slice(-10).reverse().map(d => ({
        id: d.id,
        timestamp: d.timestamp,
        syscall: d.syscall,
        process: d.process,
        pid: d.pid,
        probability: d.markov_probability,
        status: d.is_anomaly ? "ANOMALY" : "NORMAL"
      }));
    }
    
    // Default mock syscalls
    const commonSyscalls = ["read", "write", "openat", "close", "fstat", "mmap", "brk", "rt_sigaction"];
    return Array.from({ length: 8 }).map((_, i) => ({
      id: i,
      timestamp: new Date().toISOString(),
      syscall: commonSyscalls[Math.floor(Math.random() * commonSyscalls.length)],
      process: "python3",
      pid: 1234 + i,
      probability: (Math.random() * 0.3 + 0.7).toFixed(4),
      status: "Normal"
    }));
  }, [syscallData]);

  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 lg:grid-cols-3 gap-6", children: [
      /* @__PURE__ */ jsxs(DashboardPanel, { className: "lg:col-span-2 p-6", children: [
        /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between mb-6", children: [
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
            /* @__PURE__ */ jsx(Activity, { className: "w-5 h-5 text-cyan-400" }),
            /* @__PURE__ */ jsx("h3", { className: "text-lg font-medium text-slate-100", children: "Live System Call Activity" })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4 text-xs", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1", children: [
              /* @__PURE__ */ jsx("div", { className: "w-3 h-3 bg-cyan-500 rounded-full" }),
              /* @__PURE__ */ jsx("span", { className: "text-slate-400", children: "Syscall Volume" })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1", children: [
              /* @__PURE__ */ jsx("div", { className: "w-3 h-3 bg-rose-500 rounded-full" }),
              /* @__PURE__ */ jsx("span", { className: "text-slate-400", children: "Anomalies" })
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsx("div", {
          className: "h-[300px] w-full",
          children: /* @__PURE__ */ jsx(ResponsiveContainer, {
            width: "100%",
            height: "100%",
            children: /* @__PURE__ */ jsxs(AreaChart, {
              data: chartData,
              children: [
                /* @__PURE__ */ jsx("defs", {
                  children: /* @__PURE__ */ jsxs("linearGradient", {
                    id: "colorCount",
                    x1: "0",
                    y1: "0",
                    x2: "0",
                    y2: "1",
                    children: [
                      /* @__PURE__ */ jsx("stop", {
                        offset: "5%",
                        stopColor: "#00d9ff",
                        stopOpacity: 0.1
                      }),
                      /* @__PURE__ */ jsx("stop", {
                        offset: "95%",
                        stopColor: "#00d9ff",
                        stopOpacity: 0
                      })
                    ]
                  })
                }),
                /* @__PURE__ */ jsx(CartesianGrid, {
                  strokeDasharray: "0",
                  stroke: "#1e2738",
                  vertical: true,
                  opacity: 0.5
                }),
                /* @__PURE__ */ jsx(XAxis, {
                  dataKey: "time",
                  stroke: "#475569",
                  fontSize: 10,
                  tickLine: true,
                  axisLine: true,
                  interval: "preserveStartEnd",
                  tick: {
                    fill: "#64748b"
                  }
                }),
                /* @__PURE__ */ jsx(YAxis, {
                  stroke: "#475569",
                  fontSize: 10,
                  tickLine: true,
                  axisLine: true,
                  tick: {
                    fill: "#64748b"
                  }
                }),
                /* @__PURE__ */ jsx(Tooltip, {
                  contentStyle: {
                    backgroundColor: "#0f172a",
                    borderColor: "#1e293b",
                    borderRadius: "8px",
                    border: "1px solid #334155"
                  },
                  itemStyle: {
                    color: "#00d9ff",
                    fontSize: "12px"
                  },
                  labelStyle: {
                    color: "#94a3b8",
                    marginBottom: "4px"
                  }
                }),
                /* @__PURE__ */ jsx(Area, {
                  type: "monotone",
                  dataKey: "count",
                  stroke: "#00d9ff",
                  strokeWidth: 2,
                  fillOpacity: 1,
                  fill: "url(#colorCount)",
                  animationDuration: 500,
                  isAnimationActive: true
                }),
                /* @__PURE__ */ jsx(Line, {
                  type: "monotone",
                  dataKey: (v) => v.isAnomaly ? v.count : null,
                  stroke: "#f43f5e",
                  strokeWidth: 0,
                  dot: {
                    r: 6,
                    fill: "#f43f5e",
                    strokeWidth: 2,
                    stroke: "#fff"
                  },
                  activeDot: {
                    r: 8
                  }
                })
              ]
            })
          })
        })
      ] }),
      /* @__PURE__ */ jsxs(DashboardPanel, { className: "p-6", children: [
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3 mb-6", children: [
          /* @__PURE__ */ jsx(ShieldAlert, { className: "w-5 h-5 text-amber-400" }),
          /* @__PURE__ */ jsx("h3", { className: "text-lg font-medium text-slate-100", children: "Markov Chain Status" })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
          /* @__PURE__ */ jsxs("div", { className: "p-4 rounded-lg bg-slate-900/50 border border-slate-800", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between mb-2", children: [
              /* @__PURE__ */ jsx("span", { className: "text-sm text-slate-400", children: "Confidence Score" }),
              /* @__PURE__ */ jsx("span", { className: "text-sm font-mono text-cyan-400", children: "98.4%" })
            ] }),
            /* @__PURE__ */ jsx("div", { className: "w-full bg-slate-800 h-1.5 rounded-full overflow-hidden", children: /* @__PURE__ */ jsx("div", { className: "bg-cyan-500 h-full w-[98.4%]" }) })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "space-y-4", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-3", children: [
              /* @__PURE__ */ jsx("div", { className: "mt-1 p-1 rounded bg-emerald-500/10 border border-emerald-500/20", children: /* @__PURE__ */ jsx(Cpu, { className: "w-4 h-4 text-emerald-400" }) }),
              /* @__PURE__ */ jsxs("div", { children: [
                /* @__PURE__ */ jsx("p", { className: "text-sm font-medium text-slate-200", children: "Current State" }),
                /* @__PURE__ */ jsx("p", { className: "text-xs text-slate-400", children: "Process: webserver (PID: 4021)" }),
                /* @__PURE__ */ jsx("div", { className: "mt-2 inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20", children: "SYSCALL: read()" })
              ] })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "p-3 rounded-lg bg-slate-900/30 border border-dashed border-slate-700", children: [
              /* @__PURE__ */ jsx("p", { className: "text-[10px] uppercase tracking-wider text-slate-500 mb-2", children: "Predicted Next State (Markov)" }),
              /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
                /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
                  /* @__PURE__ */ jsx("span", { className: "text-xs text-slate-300", children: "write()" }),
                  /* @__PURE__ */ jsx("span", { className: "text-xs text-emerald-400", children: "82% prob." })
                ] }),
                /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
                  /* @__PURE__ */ jsx("span", { className: "text-xs text-slate-300", children: "close()" }),
                  /* @__PURE__ */ jsx("span", { className: "text-xs text-emerald-400", children: "14% prob." })
                ] }),
                /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
                  /* @__PURE__ */ jsx("span", { className: "text-xs text-slate-300", children: "execve()" }),
                  /* @__PURE__ */ jsx("span", { className: "text-xs text-rose-500", children: "< 0.001%" })
                ] })
              ] })
            ] })
          ] })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxs(DashboardPanel, { className: "p-6", children: [
      /* @__PURE__ */ jsx("h3", { className: "text-lg font-medium text-slate-100 mb-6", children: "Recent System Calls (RASP)" }),
      /* @__PURE__ */ jsx("div", { className: "overflow-x-auto", children: /* @__PURE__ */ jsxs("table", { className: "w-full text-left", children: [
        /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { className: "border-b border-slate-800", children: [
          /* @__PURE__ */ jsx("th", { className: "pb-3 text-xs font-semibold text-slate-500 uppercase", children: "Timestamp" }),
          /* @__PURE__ */ jsx("th", { className: "pb-3 text-xs font-semibold text-slate-500 uppercase", children: "Syscall" }),
          /* @__PURE__ */ jsx("th", { className: "pb-3 text-xs font-semibold text-slate-500 uppercase", children: "Process" }),
          /* @__PURE__ */ jsx("th", { className: "pb-3 text-xs font-semibold text-slate-500 uppercase", children: "PID" }),
          /* @__PURE__ */ jsx("th", { className: "pb-3 text-xs font-semibold text-slate-500 uppercase", children: "Markov Prob." }),
          /* @__PURE__ */ jsx("th", { className: "pb-3 text-xs font-semibold text-slate-500 uppercase", children: "Status" })
        ] }) }),
        /* @__PURE__ */ jsx("tbody", { className: "divide-y divide-slate-800", children: recentSyscalls.map((call, idx) => /* @__PURE__ */ jsxs("tr", { className: "group hover:bg-slate-800/30 transition-colors", children: [
          /* @__PURE__ */ jsx("td", { className: "py-3 text-sm text-slate-400 font-mono", children: call.timestamp.split("T")[1].split(".")[0] }),
          /* @__PURE__ */ jsx("td", { className: "py-3", children: /* @__PURE__ */ jsxs("span", { className: "text-sm font-mono text-cyan-400 bg-cyan-400/10 px-2 py-1 rounded", children: [
            call.syscall,
            "()"
          ] }) }),
          /* @__PURE__ */ jsx("td", { className: "py-3 text-sm text-slate-300", children: call.process }),
          /* @__PURE__ */ jsx("td", { className: "py-3 text-sm text-slate-400 font-mono", children: call.pid }),
          /* @__PURE__ */ jsx("td", { className: "py-3 text-sm", children: /* @__PURE__ */ jsx("span", { className: parseFloat(call.probability) < 0.01 ? "text-rose-500" : "text-emerald-400", children: call.probability }) }),
          /* @__PURE__ */ jsx("td", { className: "py-3", children: /* @__PURE__ */ jsx("span", { className: `text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${parseFloat(call.probability) < 0.01 ? "bg-rose-500/10 text-rose-500 border-rose-500/20" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"}`, children: parseFloat(call.probability) < 0.01 ? "ANOMALY" : "NORMAL" }) })
        ] }, idx)) })
      ] }) })
    ] })
  ] });
}
