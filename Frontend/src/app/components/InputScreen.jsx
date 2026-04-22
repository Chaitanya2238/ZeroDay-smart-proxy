import { jsx, jsxs } from "react/jsx-runtime";
import { useState } from "react";
import { motion } from "motion/react";
import { Search, Upload, Shield, Activity } from "lucide-react";
import { INPUT_INFO_CARDS } from "../lib/threats";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { DashboardPanel } from "./DashboardPanel";
function InputScreen({
  onStartScan,
  onToggleRealTime,
  isRealTimeCapture
}) {
  const [query, setQuery] = useState("");
  const [file, setFile] = useState();
  const handleSubmit = (e) => {
    e.preventDefault();
    if (query.trim() || file) {
      onStartScan({ query, file });
    }
  };
  const handleFileChange = (e) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
    }
  };
  return /* @__PURE__ */ jsxs("div", { className: "size-full flex items-center justify-center px-6 py-12 relative overflow-hidden", children: [
    /* @__PURE__ */ jsx("div", { className: "absolute inset-0 opacity-20", children: /* @__PURE__ */ jsx(
      "div",
      {
        className: "absolute inset-0",
        style: {
          backgroundImage: `linear-gradient(#00d9ff 1px, transparent 1px),
                             linear-gradient(90deg, #00d9ff 1px, transparent 1px)`,
          backgroundSize: "50px 50px"
        }
      }
    ) }),
    /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: { opacity: 0, y: 20 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.6 },
        className: "relative z-10 w-full max-w-3xl",
        children: [
          /* @__PURE__ */ jsxs("div", { className: "text-center mb-12", children: [
            /* @__PURE__ */ jsxs(
              motion.div,
              {
                initial: { scale: 0.9, opacity: 0 },
                animate: { scale: 1, opacity: 1 },
                transition: { delay: 0.2, duration: 0.5 },
                className: "inline-flex items-center gap-3 mb-6",
                children: [
                  /* @__PURE__ */ jsx(Shield, { className: "w-12 h-12", style: { color: "#00d9ff" } }),
                  /* @__PURE__ */ jsx(
                    "h1",
                    {
                      className: "text-5xl tracking-tight",
                      style: { color: "#e8edf4" },
                      children: "Threat Detection System"
                    }
                  )
                ]
              }
            ),
            /* @__PURE__ */ jsx(
              motion.p,
              {
                initial: { opacity: 0 },
                animate: { opacity: 1 },
                transition: { delay: 0.4, duration: 0.5 },
                className: "text-lg",
                style: { color: "#8b92a8" },
                children: "Real-time packet vulnerability scanner"
              }
            )
          ] }),
          /* @__PURE__ */ jsxs(
            motion.div,
            {
              initial: { opacity: 0 },
              animate: { opacity: 1 },
              transition: { delay: 0.5, duration: 0.5 },
              className: "mb-8 flex items-center justify-center gap-3",
              children: [
                /* @__PURE__ */ jsx(
                  Activity,
                  {
                    className: "w-5 h-5",
                    style: { color: isRealTimeCapture ? "#00ff88" : "#8b92a8" }
                  }
                ),
                /* @__PURE__ */ jsx(
                  Button,
                  {
                    onClick: () => onToggleRealTime(!isRealTimeCapture),
                    className: "px-6 py-2 rounded-lg transition-all",
                    style: {
                      backgroundColor: isRealTimeCapture ? "#00ff8822" : "#1a1f2e",
                      border: `1px solid ${isRealTimeCapture ? "#00ff88" : "#1e2738"}`,
                      color: isRealTimeCapture ? "#00ff88" : "#8b92a8"
                    },
                    variant: "ghost",
                    children: isRealTimeCapture ? "Real-time Capture Active" : "Enable Real-time Capture"
                  }
                )
              ]
            }
          ),
          /* @__PURE__ */ jsxs(
            motion.form,
            {
              initial: { opacity: 0, y: 20 },
              animate: { opacity: 1, y: 0 },
              transition: { delay: 0.6, duration: 0.5 },
              onSubmit: handleSubmit,
              className: "space-y-6",
              children: [
                /* @__PURE__ */ jsxs("div", { className: "relative", children: [
                  /* @__PURE__ */ jsx(
                    Search,
                    {
                      className: "absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5",
                      style: { color: "#00d9ff" }
                    }
                  ),
                  /* @__PURE__ */ jsx(
                    Input,
                    {
                      type: "text",
                      value: query,
                      onChange: (e) => setQuery(e.target.value),
                      placeholder: "Enter traffic data, packet logs, or IP address...",
                      className: "w-full rounded-xl border py-5 pr-6 pl-14 transition-all",
                      style: {
                        backgroundColor: "#0f1420",
                        borderColor: "#1e2738",
                        color: "#e8edf4",
                        boxShadow: "0 4px 20px rgba(0, 217, 255, 0.1)"
                      }
                    }
                  )
                ] }),
                /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4", children: [
                  /* @__PURE__ */ jsxs(
                    "label",
                    {
                      className: "flex-1 flex items-center justify-center gap-3 px-6 py-4 rounded-xl border cursor-pointer transition-all hover:border-[#00d9ff]",
                      style: {
                        backgroundColor: "#0f1420",
                        borderColor: file ? "#00d9ff" : "#1e2738",
                        color: file ? "#00d9ff" : "#8b92a8"
                      },
                      children: [
                        /* @__PURE__ */ jsx(Upload, { className: "w-5 h-5" }),
                        /* @__PURE__ */ jsx("span", { children: file ? file.name : "Upload .pcap, .txt, or .log file" }),
                        /* @__PURE__ */ jsx(
                          "input",
                          {
                            type: "file",
                            accept: ".pcap,.txt,.log",
                            onChange: handleFileChange,
                            className: "hidden"
                          }
                        )
                      ]
                    }
                  ),
                  /* @__PURE__ */ jsx(motion.div, { whileHover: { scale: 1.02 }, whileTap: { scale: 0.98 }, children: /* @__PURE__ */ jsx(
                    Button,
                    {
                      type: "submit",
                      className: "rounded-xl px-12 py-4 font-medium transition-all",
                      style: {
                        backgroundColor: "#00d9ff",
                        color: "#0a0e1a",
                        boxShadow: "0 4px 20px rgba(0, 217, 255, 0.4)"
                      },
                      children: "Scan"
                    }
                  ) })
                ] })
              ]
            }
          ),
          /* @__PURE__ */ jsx(
            motion.div,
            {
              initial: { opacity: 0, y: 20 },
              animate: { opacity: 1, y: 0 },
              transition: { delay: 0.8, duration: 0.5 },
              className: "mt-12 grid grid-cols-3 gap-4",
              children: INPUT_INFO_CARDS.map((item) => /* @__PURE__ */ jsxs(
                DashboardPanel,
                {
                  className: "px-6 py-4 text-center",
                  children: [
                    /* @__PURE__ */ jsx("div", { className: "text-sm", style: { color: "#8b92a8" }, children: item.label }),
                    /* @__PURE__ */ jsx("div", { className: "mt-1", style: { color: "#e8edf4" }, children: item.value })
                  ]
                },
                item.label
              ))
            }
          )
        ]
      }
    )
  ] });
}
export {
  InputScreen
};
