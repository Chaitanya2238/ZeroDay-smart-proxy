#!/usr/bin/env python3
"""Reset test state files without BOM"""
import json

# Clear proxy log
open('proxy.log', 'w').close()

# Reset alerts
with open('phase2/alerts.json', 'w') as f:
    json.dump({'alerts': []}, f)

# Reset analyzer state
with open('phase2/analyzer_state.json', 'w') as f:
    json.dump({'last_position': 0}, f)

print("✅ State files reset cleanly")
