import { motion } from "motion/react";
import type { ThreatData } from "../lib/threats";
import {
  THREAT_LEVEL_COLORS,
  THREAT_STATUS_COLORS,
} from "../lib/threats";
import { DashboardPanel } from "./DashboardPanel";

interface ThreatTableProps {
  data: ThreatData[];
}

export function ThreatTable({ data }: ThreatTableProps) {
  return (
    <DashboardPanel className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: "1px solid #1e2738" }}>
              {[
                "Log ID",
                "Packet Name",
                "Protocol",
                "Source IP",
                "Destination IP",
                "Threat Type",
                "Threat Level",
                "Confidence",
                "Status",
                "Prevention",
                "Timestamp",
              ].map((header) => (
                <th
                  key={header}
                  className="px-6 py-4 text-left text-sm"
                  style={{ color: "#8b92a8" }}
                >
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((item, index) => (
              <motion.tr
                key={item.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className="border-b transition-colors hover:bg-[#1a1f2e]"
                style={{ borderColor: "#1e2738" }}
              >
                <td className="px-6 py-4 font-mono" style={{ color: "#00d9ff" }}>
                  {item.id}
                </td>
                <td className="px-6 py-4" style={{ color: "#e8edf4" }}>
                  {item.packetName}
                </td>
                <td className="px-6 py-4">
                  <span
                    className="px-3 py-1 rounded-full text-xs font-mono"
                    style={{
                      backgroundColor: "#1a1f2e",
                      color: "#8b92a8",
                    }}
                  >
                    {item.protocol}
                  </span>
                </td>
                <td className="px-6 py-4 font-mono" style={{ color: "#8b92a8" }}>
                  {item.sourceIp}
                </td>
                <td className="px-6 py-4 font-mono" style={{ color: "#8b92a8" }}>
                  {item.destIp}
                </td>
                <td className="px-6 py-4" style={{ color: "#e8edf4" }}>
                  {item.threatType}
                </td>
                <td className="px-6 py-4">
                  <span
                    className="px-3 py-1 rounded-full text-xs uppercase"
                    style={{
                      backgroundColor: `${THREAT_LEVEL_COLORS[item.threatLevel]}22`,
                      color: THREAT_LEVEL_COLORS[item.threatLevel],
                      border: `1px solid ${THREAT_LEVEL_COLORS[item.threatLevel]}44`,
                    }}
                  >
                    {item.threatLevel}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <div
                      className="flex-1 h-2 rounded-full overflow-hidden"
                      style={{ backgroundColor: "#1a1f2e" }}
                    >
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${item.confidence}%`,
                          backgroundColor: THREAT_LEVEL_COLORS[item.threatLevel],
                        }}
                      />
                    </div>
                    <span
                      className="text-sm"
                      style={{ color: THREAT_LEVEL_COLORS[item.threatLevel] }}
                    >
                      {item.confidence}%
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span
                    className="px-3 py-1 rounded-full text-xs uppercase"
                    style={{
                      backgroundColor: `${THREAT_STATUS_COLORS[item.status]}22`,
                      color: THREAT_STATUS_COLORS[item.status],
                      border: `1px solid ${THREAT_STATUS_COLORS[item.status]}44`,
                    }}
                  >
                    {item.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm" style={{ color: "#8b92a8" }}>
                  {item.prevention}
                </td>
                <td
                  className="px-6 py-4 text-sm font-mono"
                  style={{ color: "#8b92a8" }}
                >
                  {item.timestamp}
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </DashboardPanel>
  );
}
