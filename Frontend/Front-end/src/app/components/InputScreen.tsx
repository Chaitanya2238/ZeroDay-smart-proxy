import { useState } from "react";
import { motion } from "motion/react";
import { Search, Upload, Shield, Activity } from "lucide-react";
import type { ScanInput } from "../lib/threats";
import { INPUT_INFO_CARDS } from "../lib/threats";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { DashboardPanel } from "./DashboardPanel";

interface InputScreenProps {
  onStartScan: (input: ScanInput) => void;
  onToggleRealTime: (enabled: boolean) => void;
  isRealTimeCapture: boolean;
}

export function InputScreen({
  onStartScan,
  onToggleRealTime,
  isRealTimeCapture,
}: InputScreenProps) {
  const [query, setQuery] = useState("");
  const [file, setFile] = useState<File | undefined>();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim() || file) {
      onStartScan({ query, file });
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
    }
  };

  return (
    <div className="size-full flex items-center justify-center px-6 py-12 relative overflow-hidden">
      {/* Background grid effect */}
      <div className="absolute inset-0 opacity-20">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `linear-gradient(#00d9ff 1px, transparent 1px),
                             linear-gradient(90deg, #00d9ff 1px, transparent 1px)`,
            backgroundSize: "50px 50px",
          }}
        />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative z-10 w-full max-w-3xl"
      >
        {/* Header */}
        <div className="text-center mb-12">
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="inline-flex items-center gap-3 mb-6"
          >
            <Shield className="w-12 h-12" style={{ color: "#00d9ff" }} />
            <h1
              className="text-5xl tracking-tight"
              style={{ color: "#e8edf4" }}
            >
              Threat Detection System
            </h1>
          </motion.div>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4, duration: 0.5 }}
            className="text-lg"
            style={{ color: "#8b92a8" }}
          >
            Real-time packet vulnerability scanner
          </motion.p>
        </div>

        {/* Real-time toggle */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5, duration: 0.5 }}
          className="mb-8 flex items-center justify-center gap-3"
        >
          <Activity
            className="w-5 h-5"
            style={{ color: isRealTimeCapture ? "#00ff88" : "#8b92a8" }}
          />
          <Button
            onClick={() => onToggleRealTime(!isRealTimeCapture)}
            className="px-6 py-2 rounded-lg transition-all"
            style={{
              backgroundColor: isRealTimeCapture ? "#00ff8822" : "#1a1f2e",
              border: `1px solid ${isRealTimeCapture ? "#00ff88" : "#1e2738"}`,
              color: isRealTimeCapture ? "#00ff88" : "#8b92a8",
            }}
            variant="ghost"
          >
            {isRealTimeCapture ? "Real-time Capture Active" : "Enable Real-time Capture"}
          </Button>
        </motion.div>

        {/* Search form */}
        <motion.form
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6, duration: 0.5 }}
          onSubmit={handleSubmit}
          className="space-y-6"
        >
          {/* Search input */}
          <div className="relative">
            <Search
              className="absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5"
              style={{ color: "#00d9ff" }}
            />
            <Input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Enter traffic data, packet logs, or IP address..."
              className="w-full rounded-xl border py-5 pr-6 pl-14 transition-all"
              style={{
                backgroundColor: "#0f1420",
                borderColor: "#1e2738",
                color: "#e8edf4",
                boxShadow: "0 4px 20px rgba(0, 217, 255, 0.1)",
              }}
            />
          </div>

          {/* File upload */}
          <div className="flex items-center gap-4">
            <label
              className="flex-1 flex items-center justify-center gap-3 px-6 py-4 rounded-xl border cursor-pointer transition-all hover:border-[#00d9ff]"
              style={{
                backgroundColor: "#0f1420",
                borderColor: file ? "#00d9ff" : "#1e2738",
                color: file ? "#00d9ff" : "#8b92a8",
              }}
            >
              <Upload className="w-5 h-5" />
              <span>{file ? file.name : "Upload .pcap or .txt file"}</span>
              <input
                type="file"
                accept=".pcap,.txt,.log"
                onChange={handleFileChange}
                className="hidden"
              />
            </label>

            <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
              <Button
                type="submit"
                className="rounded-xl px-12 py-4 font-medium transition-all"
                style={{
                  backgroundColor: "#00d9ff",
                  color: "#0a0e1a",
                  boxShadow: "0 4px 20px rgba(0, 217, 255, 0.4)",
                }}
              >
                Scan
              </Button>
            </motion.div>
          </div>
        </motion.form>

        {/* Info cards */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8, duration: 0.5 }}
          className="mt-12 grid grid-cols-3 gap-4"
        >
          {INPUT_INFO_CARDS.map((item) => (
            <DashboardPanel
              key={item.label}
              className="px-6 py-4 text-center"
            >
              <div className="text-sm" style={{ color: "#8b92a8" }}>
                {item.label}
              </div>
              <div className="mt-1" style={{ color: "#e8edf4" }}>
                {item.value}
              </div>
            </DashboardPanel>
          ))}
        </motion.div>
      </motion.div>
    </div>
  );
}
