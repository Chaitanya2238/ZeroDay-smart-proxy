import { jsx, jsxs } from "react/jsx-runtime";
import { useEffect, useState } from "react";
import { motion } from "motion/react";
import { Shield, Loader2 } from "lucide-react";
import {
  getScanningStatus,
  LOG_TYPE_COLORS,
  SCAN_LOGS
} from "../lib/threats";
import { DashboardPanel } from "./DashboardPanel";
function ScanningScreen() {
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  useEffect(() => {
    const progressInterval = window.setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          window.clearInterval(progressInterval);
          return 100;
        }
        return prev + 2.5;
      });
    }, 100);
    const logTimers = SCAN_LOGS.map(
      (log, index) => window.setTimeout(() => {
        setLogs((prev) => [...prev, log]);
      }, index * 300)
    );
    return () => {
      window.clearInterval(progressInterval);
      logTimers.forEach((timer) => window.clearTimeout(timer));
    };
  }, []);
  return /* @__PURE__ */ jsxs("div", { className: "size-full flex items-center justify-center px-6 py-12 relative overflow-hidden", children: [
    /* @__PURE__ */ jsx("div", { className: "absolute inset-0 opacity-10", children: /* @__PURE__ */ jsx(
      motion.div,
      {
        animate: {
          backgroundPosition: ["0% 0%", "100% 100%"]
        },
        transition: {
          duration: 20,
          repeat: Infinity,
          repeatType: "reverse"
        },
        className: "absolute inset-0",
        style: {
          backgroundImage: `linear-gradient(45deg, #00d9ff 0%, transparent 50%, #00ff88 100%)`,
          backgroundSize: "200% 200%"
        }
      }
    ) }),
    /* @__PURE__ */ jsxs("div", { className: "relative z-10 w-full max-w-4xl", children: [
      /* @__PURE__ */ jsxs(
        motion.div,
        {
          initial: { opacity: 0, y: -20 },
          animate: { opacity: 1, y: 0 },
          className: "text-center mb-12",
          children: [
            /* @__PURE__ */ jsxs("div", { className: "inline-flex items-center gap-3 mb-4", children: [
              /* @__PURE__ */ jsx(
                motion.div,
                {
                  animate: { rotate: 360 },
                  transition: { duration: 2, repeat: Infinity, ease: "linear" },
                  children: /* @__PURE__ */ jsx(Shield, { className: "w-12 h-12", style: { color: "#00d9ff" } })
                }
              ),
              /* @__PURE__ */ jsx("h1", { className: "text-4xl", style: { color: "#e8edf4" }, children: "Scanning in Progress" })
            ] }),
            /* @__PURE__ */ jsx("p", { className: "text-lg", style: { color: "#8b92a8" }, children: "Analyzing network traffic for vulnerabilities" })
          ]
        }
      ),
      /* @__PURE__ */ jsx(
        motion.div,
        {
          initial: { opacity: 0, scale: 0.95 },
          animate: { opacity: 1, scale: 1 },
          transition: { delay: 0.2 },
          children: /* @__PURE__ */ jsxs(DashboardPanel, { className: "mb-8 p-8", children: [
            /* @__PURE__ */ jsxs("div", { className: "mb-4", children: [
              /* @__PURE__ */ jsxs("div", { className: "flex justify-between mb-2", children: [
                /* @__PURE__ */ jsx("span", { style: { color: "#8b92a8" }, children: "Progress" }),
                /* @__PURE__ */ jsxs("span", { style: { color: "#00d9ff" }, children: [
                  Math.round(progress),
                  "%"
                ] })
              ] }),
              /* @__PURE__ */ jsx(
                "div",
                {
                  className: "h-3 rounded-full overflow-hidden",
                  style: { backgroundColor: "#1a1f2e" },
                  children: /* @__PURE__ */ jsx(
                    motion.div,
                    {
                      initial: { width: 0 },
                      animate: { width: `${progress}%` },
                      transition: { duration: 0.3 },
                      className: "h-full rounded-full relative",
                      style: {
                        backgroundColor: "#00d9ff",
                        boxShadow: "0 0 20px rgba(0, 217, 255, 0.6)"
                      },
                      children: /* @__PURE__ */ jsx(
                        "div",
                        {
                          className: "absolute inset-0 animate-pulse",
                          style: {
                            background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)"
                          }
                        }
                      )
                    }
                  )
                }
              )
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2 mt-6", children: [
              /* @__PURE__ */ jsx(
                Loader2,
                {
                  className: "w-5 h-5 animate-spin",
                  style: { color: "#00d9ff" }
                }
              ),
              /* @__PURE__ */ jsx("span", { style: { color: "#e8edf4" }, children: getScanningStatus(progress) })
            ] })
          ] })
        }
      ),
      /* @__PURE__ */ jsx(
        motion.div,
        {
          initial: { opacity: 0, y: 20 },
          animate: { opacity: 1, y: 0 },
          transition: { delay: 0.4 },
          children: /* @__PURE__ */ jsxs(DashboardPanel, { className: "p-6", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2 mb-4", children: [
              /* @__PURE__ */ jsx(
                "div",
                {
                  className: "w-2 h-2 rounded-full animate-pulse",
                  style: { backgroundColor: "#00ff88" }
                }
              ),
              /* @__PURE__ */ jsx("span", { style: { color: "#8b92a8" }, children: "Live System Log" })
            ] }),
            /* @__PURE__ */ jsx(
              "div",
              {
                className: "space-y-2 font-mono text-sm overflow-y-auto",
                style: { maxHeight: "300px" },
                children: logs.map((log, index) => /* @__PURE__ */ jsxs(
                  motion.div,
                  {
                    initial: { opacity: 0, x: -10 },
                    animate: { opacity: 1, x: 0 },
                    transition: { duration: 0.3 },
                    className: "flex items-start gap-3",
                    children: [
                      /* @__PURE__ */ jsxs("span", { style: { color: LOG_TYPE_COLORS[log.type] }, children: [
                        "[",
                        log.type.toUpperCase(),
                        "]"
                      ] }),
                      /* @__PURE__ */ jsx("span", { style: { color: "#e8edf4" }, children: log.message })
                    ]
                  },
                  index
                ))
              }
            )
          ] })
        }
      )
    ] })
  ] });
}
export {
  ScanningScreen
};
