import { jsx, jsxs } from "react/jsx-runtime";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import {
  getAttackTypeCounts,
  getThreatDistribution
} from "../lib/threats";
import { DashboardPanel } from "./DashboardPanel";
function ThreatChartTooltip({
  active,
  payload
}) {
  if (!active || !payload?.length) {
    return null;
  }
  const item = payload[0];
  const label = typeof item.name === "string" ? item.name : "";
  const value = item.value;
  const suffix = item.dataKey === "count" ? "attacks" : "threats";
  const color = typeof item.payload?.color === "string" ? item.payload.color : item.fill;
  return /* @__PURE__ */ jsxs(
    "div",
    {
      className: "rounded-lg border px-4 py-2",
      style: {
        backgroundColor: "#0f1420",
        borderColor: "#1e2738",
        color: "#e8edf4"
      },
      children: [
        /* @__PURE__ */ jsx("p", { className: "font-medium", children: label }),
        /* @__PURE__ */ jsxs("p", { style: { color }, children: [
          value,
          " ",
          suffix
        ] })
      ]
    }
  );
}
function ThreatCharts({ data }) {
  const threatDistribution = getThreatDistribution(data);
  const attackTypes = getAttackTypeCounts(data);
  return /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-2 gap-6", children: [
    /* @__PURE__ */ jsxs(DashboardPanel, { className: "p-6", children: [
      /* @__PURE__ */ jsx("h3", { className: "text-lg mb-6", style: { color: "#e8edf4" }, children: "Threat Distribution" }),
      /* @__PURE__ */ jsx(ResponsiveContainer, { width: "100%", height: 300, children: /* @__PURE__ */ jsxs(PieChart, { children: [
        /* @__PURE__ */ jsx(
          Pie,
          {
            data: threatDistribution,
            cx: "50%",
            cy: "50%",
            innerRadius: 60,
            outerRadius: 100,
            paddingAngle: 2,
            dataKey: "value",
            children: threatDistribution.map((entry, index) => /* @__PURE__ */ jsx(Cell, { fill: entry.color }, `pie-cell-${index}`))
          }
        ),
        /* @__PURE__ */ jsx(Tooltip, { content: /* @__PURE__ */ jsx(ThreatChartTooltip, {}) })
      ] }) }),
      /* @__PURE__ */ jsx("div", { className: "grid grid-cols-2 gap-4 mt-6", children: threatDistribution.map((item) => /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsx(
          "div",
          {
            className: "w-3 h-3 rounded-full",
            style: { backgroundColor: item.color }
          }
        ),
        /* @__PURE__ */ jsx("span", { className: "text-sm", style: { color: "#8b92a8" }, children: item.name }),
        /* @__PURE__ */ jsx("span", { className: "text-sm ml-auto", style: { color: item.color }, children: item.value })
      ] }, `legend-${item.name}`)) })
    ] }),
    /* @__PURE__ */ jsxs(DashboardPanel, { className: "p-6", children: [
      /* @__PURE__ */ jsx("h3", { className: "text-lg mb-6", style: { color: "#e8edf4" }, children: "Attacks by Type" }),
      /* @__PURE__ */ jsx(ResponsiveContainer, { width: "100%", height: 300, children: /* @__PURE__ */ jsxs(BarChart, { data: attackTypes, children: [
        /* @__PURE__ */ jsx(
          XAxis,
          {
            dataKey: "name",
            tick: { fill: "#8b92a8", fontSize: 12 },
            angle: -45,
            textAnchor: "end",
            height: 80
          }
        ),
        /* @__PURE__ */ jsx(YAxis, { tick: { fill: "#8b92a8", fontSize: 12 } }),
        /* @__PURE__ */ jsx(Tooltip, { content: /* @__PURE__ */ jsx(ThreatChartTooltip, {}) }),
        /* @__PURE__ */ jsx(Bar, { dataKey: "count", radius: [8, 8, 0, 0], children: attackTypes.map((entry, index) => /* @__PURE__ */ jsx(Cell, { fill: entry.color }, `bar-cell-${index}`)) })
      ] }) })
    ] })
  ] });
}
export {
  ThreatCharts
};
