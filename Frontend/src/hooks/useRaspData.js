import { useEffect, useState, useRef } from "react";

/**
 * Custom hook for live RASP (Runtime Application Self-Protection) data
 * Simulates real-time system call monitoring with Markov Chain probability
 */
export function useRaspData(isActive = false) {
  const [syscalls, setSyscalls] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const intervalRef = useRef(null);

  useEffect(() => {
    if (!isActive) {
      if (intervalRef.current) clearInterval(intervalRef.current);
      return;
    }

    setIsLoading(true);
    
    // Initial fetch (mocking API call)
    const initialData = generateMockSyscalls(20);
    setSyscalls(initialData);
    setIsLoading(false);

    // Set up polling for new "live" data
    intervalRef.current = setInterval(() => {
      const newSyscall = generateMockSyscalls(1)[0];
      setSyscalls(prev => {
        const updated = [...prev, newSyscall];
        // Keep only last 50 for performance
        return updated.slice(-50);
      });
    }, 2000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isActive]);

  return { syscalls, isLoading };
}

function generateMockSyscalls(count) {
  const commonSyscalls = [
    "read", "write", "openat", "close", "fstat", "mmap", 
    "brk", "rt_sigaction", "ioctl", "recvfrom", "sendto"
  ];
  
  const suspiciousSequences = [
    { seq: ["accept4", "execve"], prob: 0.0001 },
    { seq: ["openat", "ptrace"], prob: 0.0005 },
    { seq: ["write", "chmod"], prob: 0.001 }
  ];

  // Logic for "standard" syscall volume:
  // Baseline is low (5-15), with occasional bursts (30-60)
  return Array.from({ length: count }).map((_, i) => {
    const isAnomaly = Math.random() > 0.97;
    const isBurst = Math.random() > 0.8;
    
    const syscall = isAnomaly 
      ? suspiciousSequences[Math.floor(Math.random() * suspiciousSequences.length)].seq[1]
      : commonSyscalls[Math.floor(Math.random() * commonSyscalls.length)];
    
    // Calculate a more "standard" volume
    const baseVolume = 8;
    const noise = Math.floor(Math.random() * 6);
    const burstVolume = isBurst ? Math.floor(Math.random() * 40) + 20 : 0;
    const finalVolume = baseVolume + noise + burstVolume;

    return {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      syscall: syscall,
      process: "nginx",
      pid: 4021,
      markov_probability: isAnomaly ? (Math.random() * 0.005).toFixed(5) : (Math.random() * 0.4 + 0.6).toFixed(4),
      is_anomaly: isAnomaly,
      syscall_count: finalVolume
    };
  });
}
