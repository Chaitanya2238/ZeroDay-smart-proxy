import { useEffect, useState } from "react";
import { motion } from "motion/react";
import { Shield, Loader2 } from "lucide-react";
import {
  getScanningStatus,
  LOG_TYPE_COLORS,
  SCAN_LOGS,
  type LogEntry,
} from "../lib/threats";
import { DashboardPanel } from "./DashboardPanel";

export function ScanningScreen() {
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);

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

    const logTimers = SCAN_LOGS.map((log, index) =>
      window.setTimeout(() => {
        setLogs((prev) => [...prev, log]);
      }, index * 300),
    );

    return () => {
      window.clearInterval(progressInterval);
      logTimers.forEach((timer) => window.clearTimeout(timer));
    };
  }, []);

  return (
    <div className="size-full flex items-center justify-center px-6 py-12 relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0 opacity-10">
        <motion.div
          animate={{
            backgroundPosition: ["0% 0%", "100% 100%"],
          }}
          transition={{
            duration: 20,
            repeat: Infinity,
            repeatType: "reverse",
          }}
          className="absolute inset-0"
          style={{
            backgroundImage: `linear-gradient(45deg, #00d9ff 0%, transparent 50%, #00ff88 100%)`,
            backgroundSize: "200% 200%",
          }}
        />
      </div>

      <div className="relative z-10 w-full max-w-4xl">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center gap-3 mb-4">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
            >
              <Shield className="w-12 h-12" style={{ color: "#00d9ff" }} />
            </motion.div>
            <h1 className="text-4xl" style={{ color: "#e8edf4" }}>
              Scanning in Progress
            </h1>
          </div>
          <p className="text-lg" style={{ color: "#8b92a8" }}>
            Analyzing network traffic for vulnerabilities
          </p>
        </motion.div>

        {/* Progress section */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
        >
          <DashboardPanel className="mb-8 p-8">
          {/* Progress bar */}
          <div className="mb-4">
            <div className="flex justify-between mb-2">
              <span style={{ color: "#8b92a8" }}>Progress</span>
              <span style={{ color: "#00d9ff" }}>{Math.round(progress)}%</span>
            </div>
            <div
              className="h-3 rounded-full overflow-hidden"
              style={{ backgroundColor: "#1a1f2e" }}
            >
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.3 }}
                className="h-full rounded-full relative"
                style={{
                  backgroundColor: "#00d9ff",
                  boxShadow: "0 0 20px rgba(0, 217, 255, 0.6)",
                }}
              >
                <div
                  className="absolute inset-0 animate-pulse"
                  style={{
                    background:
                      "linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)",
                  }}
                />
              </motion.div>
            </div>
          </div>

          {/* Status text */}
          <div className="flex items-center gap-2 mt-6">
            <Loader2
              className="w-5 h-5 animate-spin"
              style={{ color: "#00d9ff" }}
            />
            <span style={{ color: "#e8edf4" }}>
              {getScanningStatus(progress)}
            </span>
          </div>
          </DashboardPanel>
        </motion.div>

        {/* Live log panel */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <DashboardPanel className="p-6">
          <div className="flex items-center gap-2 mb-4">
            <div
              className="w-2 h-2 rounded-full animate-pulse"
              style={{ backgroundColor: "#00ff88" }}
            />
            <span style={{ color: "#8b92a8" }}>Live System Log</span>
          </div>

          <div
            className="space-y-2 font-mono text-sm overflow-y-auto"
            style={{ maxHeight: "300px" }}
          >
            {logs.map((log, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
                className="flex items-start gap-3"
              >
                <span style={{ color: LOG_TYPE_COLORS[log.type] }}>
                  [{log.type.toUpperCase()}]
                </span>
                <span style={{ color: "#e8edf4" }}>{log.message}</span>
              </motion.div>
            ))}
          </div>
          </DashboardPanel>
        </motion.div>
      </div>
    </div>
  );
}
