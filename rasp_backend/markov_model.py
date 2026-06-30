# rasp_backend/markov_model.py
"""
Markov Chain model for privilege escalation detection on Windows
"""
import re
from collections import defaultdict, Counter
import pickle
import os

class PrivEscMarkovModel:
    def __init__(self, order=2):
        self.order = order
        self.transitions = defaultdict(Counter)
        self.token_counts = Counter()
        self.is_trained = False
        
        # Token definitions for process names and sequences
        self.token_map = {
            # Privilege escalation related process names
            "cmd": ["cmd", "cmd.exe"],
            "powershell": ["powershell", "powershell.exe", "pwsh", "pwsh.exe"],
            "whoami": ["whoami", "whoami.exe"],
            "net": ["net", "net.exe"],
            "schtasks": ["schtasks", "schtasks.exe"],
            "sc": ["sc", "sc.exe"],
            "reg": ["reg", "reg.exe"],
            "systeminfo": ["systeminfo", "systeminfo.exe"],
            "tasklist": ["tasklist", "tasklist.exe"],
            "rundll32": ["rundll32", "rundll32.exe"],
            "wmic": ["wmic", "wmic.exe"],
            "mshta": ["mshta", "mshta.exe"],
            # Normal processes
            "explorer": ["explorer", "explorer.exe"],
            "chrome": ["chrome", "chrome.exe"],
            "python": ["python", "python.exe", "pythonw.exe"],
            "node": ["node", "node.exe"],
            "system": ["system", "system idle process", "svchost"],
        }

    def _tokenize_process(self, proc_name):
        """Convert a process name to our standard token"""
        proc_lower = proc_name.lower()
        for token, aliases in self.token_map.items():
            if proc_lower in aliases or token in proc_lower:
                return token
        return "other"

    def train(self, process_sequences):
        """
        Train the Markov model on normal sequences
        process_sequences: list of lists of process names in chronological order
        """
        for sequence in process_sequences:
            tokens = [self._tokenize_process(p) for p in sequence]
            for i in range(len(tokens) - self.order):
                context = tuple(tokens[i:i+self.order])
                next_token = tokens[i+self.order]
                self.transitions[context][next_token] += 1
                self.token_counts[next_token] += 1
        self.is_trained = True
        return self

    def calculate_probability(self, sequence):
        """
        Calculate probability of a sequence being normal
        Returns (average_probability, individual_token_probs)
        """
        if not self.is_trained:
            return 1.0, [1.0]*len(sequence)
        
        tokens = [self._tokenize_process(p) for p in sequence]
        if len(tokens) <= self.order:
            return 0.9, [0.9]*len(tokens)
        
        probabilities = []
        for i in range(len(tokens) - self.order):
            context = tuple(tokens[i:i+self.order])
            next_token = tokens[i+self.order]
            
            if context not in self.transitions or next_token not in self.transitions[context]:
                # Smoothing for unknown transitions
                total_next_tokens = sum(self.token_counts.values())
                prob = 1.0 / (total_next_tokens + 1) if total_next_tokens > 0 else 0.01
            else:
                total_context = sum(self.transitions[context].values())
                prob = self.transitions[context][next_token] / total_context
            
            probabilities.append(prob)
        
        if probabilities:
            avg_prob = sum(probabilities)/len(probabilities)
        else:
            avg_prob = 0.5
        
        # Return average and individual per-token probs
        return avg_prob, probabilities

    def is_anomaly(self, sequence, threshold=0.01):
        """
        Determine if a sequence is anomalous
        threshold: probability below this is considered anomaly
        """
        avg_prob, token_probs = self.calculate_probability(sequence)
        return avg_prob < threshold, avg_prob

    def save_model(self, filepath):
        with open(filepath, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load_model(cls, filepath):
        if not os.path.exists(filepath):
            # Initialize with default training data if no saved model
            model = cls()
            # Default normal sequences for Windows
            normal_sequences = [
                ["explorer", "chrome", "system"],
                ["explorer", "python", "system"],
                ["system", "explorer", "python"],
                ["chrome", "explorer", "system"],
                ["system", "svchost", "explorer"],
            ]
            model.train(normal_sequences)
            model.save_model(filepath)
            return model
        with open(filepath, "rb") as f:
            return pickle.load(f)
