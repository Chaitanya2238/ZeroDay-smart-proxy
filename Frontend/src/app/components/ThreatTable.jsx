import { jsx, jsxs } from "react/jsx-runtime";
import { motion } from "motion/react";
import {
  THREAT_LEVEL_COLORS,
  THREAT_STATUS_COLORS
} from "../lib/threats";
import { DashboardPanel } from "./DashboardPanel";
function ThreatTable({ data }) {
  return /* @__PURE__ */ jsx(DashboardPanel, { className: "overflow-hidden", children: /* @__PURE__ */ jsx("div", { className: "overflow-x-auto", children: /* @__PURE__ */ jsxs("table", { className: "w-full", children: [
    /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsx("tr", { style: { borderBottom: "1px solid #1e2738" }, children: [
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
      "Timestamp"
    ].map((header) => /* @__PURE__ */ jsx(
      "th",
      {
        className: "px-6 py-4 text-left text-sm",
        style: { color: "#8b92a8" },
        children: header
      },
      header
    )) }) }),
    /* @__PURE__ */ jsx("tbody", { children: data.map((item, index) => /* @__PURE__ */ jsxs(
      motion.tr,
      {
        initial: { opacity: 0, y: 10 },
        animate: { opacity: 1, y: 0 },
        transition: { delay: index * 0.05 },
        className: "border-b transition-colors hover:bg-[#1a1f2e]",
        style: { borderColor: "#1e2738" },
        children: [
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4 font-mono", style: { color: "#00d9ff" }, children: item.id }),
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4", style: { color: "#e8edf4" }, children: item.packetName }),
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4", children: /* @__PURE__ */ jsx(
            "span",
            {
              className: "px-3 py-1 rounded-full text-xs font-mono",
              style: {
                backgroundColor: "#1a1f2e",
                color: "#8b92a8"
              },
              children: item.protocol
            }
          ) }),
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4 font-mono", style: { color: "#8b92a8" }, children: item.sourceIp }),
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4 font-mono", style: { color: "#8b92a8" }, children: item.destIp }),
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4", style: { color: "#e8edf4" }, children: item.threatType }),
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4", children: /* @__PURE__ */ jsx(
            "span",
            {
              className: "px-3 py-1 rounded-full text-xs uppercase",
              style: {
                backgroundColor: `${THREAT_LEVEL_COLORS[item.threatLevel]}22`,
                color: THREAT_LEVEL_COLORS[item.threatLevel],
                border: `1px solid ${THREAT_LEVEL_COLORS[item.threatLevel]}44`
              },
              children: item.threatLevel
            }
          ) }),
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4", children: /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsx(
              "div",
              {
                className: "flex-1 h-2 rounded-full overflow-hidden",
                style: { backgroundColor: "#1a1f2e" },
                children: /* @__PURE__ */ jsx(
                  "div",
                  {
                    className: "h-full rounded-full",
                    style: {
                      width: `${item.confidence}%`,
                      backgroundColor: THREAT_LEVEL_COLORS[item.threatLevel]
                    }
                  }
                )
              }
            ),
            /* @__PURE__ */ jsxs(
              "span",
              {
                className: "text-sm",
                style: { color: THREAT_LEVEL_COLORS[item.threatLevel] },
                children: [
                  item.confidence,
                  "%"
                ]
              }
            )
          ] }) }),
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4", children: /* @__PURE__ */ jsx(
            "span",
            {
              className: "px-3 py-1 rounded-full text-xs uppercase",
              style: {
                backgroundColor: `${THREAT_STATUS_COLORS[item.status]}22`,
                color: THREAT_STATUS_COLORS[item.status],
                border: `1px solid ${THREAT_STATUS_COLORS[item.status]}44`
              },
              children: item.status
            }
          ) }),
          /* @__PURE__ */ jsx("td", { className: "px-6 py-4 text-sm", style: { color: "#8b92a8" }, children: item.prevention }),
          /* @__PURE__ */ jsx(
            "td",
            {
              className: "px-6 py-4 text-sm font-mono",
              style: { color: "#8b92a8" },
              children: item.timestamp
            }
          )
        ]
      },
      item.id
    )) })
  ] }) }) });
}
export {
  ThreatTable
};
