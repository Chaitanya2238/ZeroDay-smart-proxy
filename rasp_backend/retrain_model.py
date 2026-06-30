#!/usr/bin/env python3
# Retrain RASP Markov model with better normal sequences
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from markov_model import PrivEscMarkovModel

print("Retraining RASP Markov model...")

# Better normal sequences - including common Windows processes
normal_sequences = [
    ["explorer", "chrome", "system"],
    ["explorer", "python", "system"],
    ["system", "explorer", "python"],
    ["chrome", "explorer", "system"],
    ["system", "svchost", "explorer"],
    ["explorer", "system", "svchost"],
    ["svchost", "system", "explorer"],
    ["python", "system", "explorer"],
    ["explorer", "chrome", "system"],
    ["system", "python", "chrome"],
    ["explorer", "system", "python"],
    ["system", "explorer", "svchost"],
    ["chrome", "system", "explorer"]
]

model = PrivEscMarkovModel()
model.train(normal_sequences)
model.save_model(os.path.join(os.path.dirname(__file__), "markov_model.pkl"))

print("RASP Markov model retrained successfully!")
print("  New normal sequences include common Windows processes")
