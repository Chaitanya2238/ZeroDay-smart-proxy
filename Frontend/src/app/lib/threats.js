import { AlertTriangle, CheckCircle, Shield } from "lucide-react";
const THREAT_LEVEL_COLORS = {
  critical: "#ff4757",
  high: "#ff6b81",
  medium: "#ffd93d",
  low: "#00d9ff",
  safe: "#00ff88"
};
const THREAT_STATUS_COLORS = {
  blocked: "#ff4757",
  monitored: "#ffd93d",
  allowed: "#00ff88"
};
const LOG_TYPE_COLORS = {
  info: "#00d9ff",
  alert: "#ff4757",
  warning: "#ffd93d"
};
const INPUT_INFO_CARDS = [
  { label: "Supported Formats", value: ".pcap, .txt, .log" },
  { label: "Detection Capability", value: "Zero-Day Threats" },
  { label: "Average Scan Time", value: "< 5 seconds" }
];
const SCAN_LOGS = [
  { type: "info", message: "Initializing packet analyzer..." },
  { type: "info", message: "Parsing network traffic data..." },
  { type: "info", message: "Analyzing TCP/IP packets..." },
  { type: "alert", message: "Suspicious pattern detected in packet 0x4A2F" },
  { type: "info", message: "Scanning for SQL injection patterns..." },
  { type: "warning", message: "Potential XSS vector identified" },
  { type: "info", message: "Checking for SSRF vulnerabilities..." },
  { type: "alert", message: "Critical threat detected: RCE attempt" },
  { type: "info", message: "Analyzing source IP geolocation..." },
  { type: "info", message: "Generating threat assessment report..." },
  { type: "info", message: "Calculating confidence scores..." },
  { type: "info", message: "Finalizing scan results..." }
];
const MOCK_THREAT_DATA = [
  {
    id: "0x4A2F",
    packetName: "HTTP_POST_REQ",
    protocol: "HTTP",
    sourceIp: "192.168.1.45",
    destIp: "10.0.0.12",
    threatType: "SQL Injection",
    threatLevel: "critical",
    confidence: 98,
    status: "blocked",
    prevention: "WAF Rule Applied",
    timestamp: "2026-04-13 14:23:41"
  },
  {
    id: "0x8B1C",
    packetName: "TCP_SYN_FLOOD",
    protocol: "TCP",
    sourceIp: "203.0.113.89",
    destIp: "10.0.0.12",
    threatType: "DDoS Attack",
    threatLevel: "critical",
    confidence: 95,
    status: "blocked",
    prevention: "Rate Limiting",
    timestamp: "2026-04-13 14:23:38"
  },
  {
    id: "0x2C9A",
    packetName: "HTTP_GET_REQ",
    protocol: "HTTP",
    sourceIp: "198.51.100.23",
    destIp: "10.0.0.15",
    threatType: "XSS Attempt",
    threatLevel: "high",
    confidence: 87,
    status: "blocked",
    prevention: "Input Sanitization",
    timestamp: "2026-04-13 14:23:35"
  },
  {
    id: "0x7F3E",
    packetName: "DNS_QUERY",
    protocol: "DNS",
    sourceIp: "192.168.1.67",
    destIp: "8.8.8.8",
    threatType: "DNS Tunneling",
    threatLevel: "medium",
    confidence: 72,
    status: "monitored",
    prevention: "Alert Generated",
    timestamp: "2026-04-13 14:23:32"
  },
  {
    id: "0x9D5B",
    packetName: "HTTPS_POST",
    protocol: "HTTPS",
    sourceIp: "172.16.0.88",
    destIp: "10.0.0.20",
    threatType: "SSRF Attempt",
    threatLevel: "medium",
    confidence: 68,
    status: "monitored",
    prevention: "URL Validation",
    timestamp: "2026-04-13 14:23:29"
  },
  {
    id: "0x1A8F",
    packetName: "TCP_CONN",
    protocol: "TCP",
    sourceIp: "192.168.1.100",
    destIp: "10.0.0.25",
    threatType: "Port Scan",
    threatLevel: "low",
    confidence: 55,
    status: "monitored",
    prevention: "Logged",
    timestamp: "2026-04-13 14:23:26"
  },
  {
    id: "0x3E7C",
    packetName: "HTTP_GET",
    protocol: "HTTP",
    sourceIp: "192.168.1.15",
    destIp: "10.0.0.30",
    threatType: "None",
    threatLevel: "safe",
    confidence: 99,
    status: "allowed",
    prevention: "N/A",
    timestamp: "2026-04-13 14:23:23"
  },
  {
    id: "0x6B2D",
    packetName: "SMTP_RELAY",
    protocol: "SMTP",
    sourceIp: "198.51.100.45",
    destIp: "10.0.0.35",
    threatType: "Phishing",
    threatLevel: "high",
    confidence: 91,
    status: "blocked",
    prevention: "Email Filter",
    timestamp: "2026-04-13 14:23:20"
  }
];
const THREAT_LEVEL_OPTIONS = [
  { value: "all", label: "All Levels" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "safe", label: "Safe" }
];
function getThreatStats(data) {
  const total = data.length;
  const threats = data.filter((item) => item.threatLevel !== "safe").length;
  const critical = data.filter((item) => item.threatLevel === "critical").length;
  const safe = Math.round(
    data.filter((item) => item.threatLevel === "safe").length / total * 100
  );
  return { total, threats, critical, safe };
}
function getStatsCards(data) {
  const stats = getThreatStats(data);
  return [
    {
      label: "Total Packets Scanned",
      value: stats.total.toLocaleString(),
      color: THREAT_LEVEL_COLORS.low,
      icon: Shield
    },
    {
      label: "Threats Detected",
      value: stats.threats.toLocaleString(),
      color: THREAT_LEVEL_COLORS.medium,
      icon: AlertTriangle
    },
    {
      label: "Critical Alerts",
      value: stats.critical.toLocaleString(),
      color: THREAT_LEVEL_COLORS.critical,
      icon: AlertTriangle
    },
    {
      label: "Safe Percentage",
      value: `${stats.safe}%`,
      color: THREAT_LEVEL_COLORS.safe,
      icon: CheckCircle
    }
  ];
}
function getFilteredThreatData(data, level) {
  if (level === "all") {
    return data;
  }
  return data.filter((item) => item.threatLevel === level);
}
function getThreatDistribution(data) {
  return [
    { name: "Critical", value: data.filter((item) => item.threatLevel === "critical").length, color: THREAT_LEVEL_COLORS.critical },
    { name: "High", value: data.filter((item) => item.threatLevel === "high").length, color: THREAT_LEVEL_COLORS.high },
    { name: "Medium", value: data.filter((item) => item.threatLevel === "medium").length, color: THREAT_LEVEL_COLORS.medium },
    { name: "Low", value: data.filter((item) => item.threatLevel === "low").length, color: THREAT_LEVEL_COLORS.low },
    { name: "Safe", value: data.filter((item) => item.threatLevel === "safe").length, color: THREAT_LEVEL_COLORS.safe }
  ];
}
function getAttackTypeCounts(data) {
  const counts = /* @__PURE__ */ new Map();
  data.forEach((item) => {
    if (item.threatLevel === "safe" || item.threatType === "None") {
      return;
    }
    counts.set(item.threatType, (counts.get(item.threatType) ?? 0) + 1);
  });
  return Array.from(counts.entries()).map(([name, count]) => ({
    name,
    count,
    color: THREAT_LEVEL_COLORS[data.find((item) => item.threatType === name)?.threatLevel ?? "low"]
  }));
}
function getScanningStatus(progress) {
  if (progress < 30) {
    return "Parsing packet data...";
  }
  if (progress < 60) {
    return "Analyzing traffic patterns...";
  }
  if (progress < 90) {
    return "Identifying threats...";
  }
  return "Generating report...";
}
export {
  INPUT_INFO_CARDS,
  LOG_TYPE_COLORS,
  MOCK_THREAT_DATA,
  SCAN_LOGS,
  THREAT_LEVEL_COLORS,
  THREAT_LEVEL_OPTIONS,
  THREAT_STATUS_COLORS,
  getAttackTypeCounts,
  getFilteredThreatData,
  getScanningStatus,
  getStatsCards,
  getThreatDistribution,
  getThreatStats
};
