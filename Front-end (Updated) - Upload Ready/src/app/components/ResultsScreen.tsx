import { useMemo, useState } from "react";
import { motion } from "motion/react";
import {
  Shield,
  Activity,
  Download,
  CheckCircle,
  Filter,
} from "lucide-react";
import { ThreatTable } from "./ThreatTable";
import { ThreatCharts } from "./ThreatCharts";
import {
  getFilteredThreatData,
  getStatsCards,
  getThreatStats,
  MOCK_THREAT_DATA,
  THREAT_LEVEL_OPTIONS,
  type ThreatLevel,
} from "../lib/threats";
import { Button } from "./ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";
import { DashboardPanel } from "./DashboardPanel";

interface ResultsScreenProps {
  onNewScan: () => void;
  isRealTimeCapture: boolean;
  onToggleRealTime: (enabled: boolean) => void;
}

export function ResultsScreen({
  onNewScan,
  isRealTimeCapture,
  onToggleRealTime,
}: ResultsScreenProps) {
  const [filterLevel, setFilterLevel] = useState<ThreatLevel | "all">("all");

  const filteredData = useMemo(
    () => getFilteredThreatData(MOCK_THREAT_DATA, filterLevel),
    [filterLevel],
  );
  const stats = useMemo(() => getThreatStats(MOCK_THREAT_DATA), []);
  const statCards = useMemo(() => getStatsCards(MOCK_THREAT_DATA), []);

  return (
    <div className="size-full overflow-y-auto px-6 py-8">
      <div className="max-w-[1600px] mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-4">
              <Shield className="w-10 h-10" style={{ color: "#00d9ff" }} />
              <div>
                <h1 className="text-3xl" style={{ color: "#e8edf4" }}>
                  Threat Detection System
                </h1>
                <p style={{ color: "#8b92a8" }}>Real-time vulnerability analysis</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Button
                onClick={() => onToggleRealTime(!isRealTimeCapture)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg transition-all"
                style={{
                  backgroundColor: isRealTimeCapture ? "#00ff8822" : "#1a1f2e",
                  border: `1px solid ${isRealTimeCapture ? "#00ff88" : "#1e2738"}`,
                  color: isRealTimeCapture ? "#00ff88" : "#8b92a8",
                }}
                variant="ghost"
              >
                <Activity className="w-4 h-4" />
                {isRealTimeCapture ? "Real-time Active" : "Real-time"}
              </Button>
              <Button
                onClick={onNewScan}
                className="px-6 py-2 rounded-lg transition-all"
                style={{
                  backgroundColor: "#00d9ff",
                  color: "#0a0e1a",
                }}
              >
                New Scan
              </Button>
            </div>
          </div>

          {/* Success banner */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 }}
            className="px-6 py-4 rounded-lg border flex items-center gap-3"
            style={{
              backgroundColor: "#00ff8811",
              borderColor: "#00ff88",
            }}
          >
            <CheckCircle className="w-5 h-5" style={{ color: "#00ff88" }} />
            <span style={{ color: "#00ff88" }}>
              Scan completed successfully — {stats.threats} threats detected
            </span>
          </motion.div>
        </motion.div>

        {/* Stats grid */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="grid grid-cols-4 gap-4 mb-8"
        >
          {statCards.map((stat, index) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.4 + index * 0.1 }}
            >
              <DashboardPanel className="p-6">
                <div className="mb-3 flex items-start justify-between">
                  <stat.icon className="h-5 w-5" style={{ color: stat.color }} />
                </div>
                <div className="mb-1 text-3xl" style={{ color: stat.color }}>
                  {stat.value}
                </div>
                <div className="text-sm" style={{ color: "#8b92a8" }}>
                  {stat.label}
                </div>
              </DashboardPanel>
            </motion.div>
          ))}
        </motion.div>

        {/* Charts section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
          className="mb-8"
        >
          <ThreatCharts data={MOCK_THREAT_DATA} />
        </motion.div>

        {/* Table section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.9 }}
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl" style={{ color: "#e8edf4" }}>
              Detected Vulnerabilities
            </h2>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4" style={{ color: "#8b92a8" }} />
                <Select
                  value={filterLevel}
                  onValueChange={(value) =>
                    setFilterLevel(value as ThreatLevel | "all")
                  }
                >
                  <SelectTrigger
                    className="w-[180px] rounded-lg border"
                    style={{
                      backgroundColor: "#0f1420",
                      borderColor: "#1e2738",
                      color: "#e8edf4",
                    }}
                  >
                    <SelectValue placeholder="All Levels" />
                  </SelectTrigger>
                  <SelectContent>
                    {THREAT_LEVEL_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <Button
                className="flex items-center gap-2 px-4 py-2 rounded-lg border transition-all hover:border-[#00d9ff]"
                style={{
                  backgroundColor: "#0f1420",
                  borderColor: "#1e2738",
                  color: "#8b92a8",
                }}
                variant="ghost"
              >
                <Download className="w-4 h-4" />
                Export CSV
              </Button>
            </div>
          </div>

          <ThreatTable data={filteredData} />
        </motion.div>
      </div>
    </div>
  );
}
