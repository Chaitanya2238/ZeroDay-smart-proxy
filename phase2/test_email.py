
# Test Email Alert Script
import os
import sys
from datetime import datetime

# Add the parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from phase2.email_alerts import send_threat_email, send_rasp_alert_email

print("Testing Email Alert System...")
print("=" * 60)

# Test a network-level threat alert
print("\n1. Testing Network Threat Alert...")
test_network_alert = {
    'alert_id': 1,
    'timestamp': datetime.now().isoformat(),
    'severity': 8,
    'threat_type': 'ZERO_DAY_SUSPICIOUS',
    'confidence': 0.9,
    'is_zeroday': True,
    'original_request': {
        'method': 'POST',
        'path': '/api/v1/login',
        'body_preview': "username' OR 1=1 --",
        'client_ip': '192.168.1.100',
        'user_agent': 'Mozilla/5.0...',
        'response_status': 200
    },
    'tier1_analysis': {
        'category': 'SQL_INJECTION',
        'severity': 7,
        'reason': 'Suspicious SQL patterns detected in request body'
    },
    'tier2_analysis': {
        'threat_type': 'ZERO_DAY_ANOMALY',
        'confidence': 0.95,
        'reasoning': 'Isolation Forest detected unusual request pattern'
    },
    'recommended_action': 'block'
}

print("   - Sending test network threat email...")
send_threat_email(test_network_alert)

# Test a RASP alert
print("\n2. Testing RASP Alert...")
test_rasp_alert = {
    'alert_id': 2,
    'timestamp': datetime.now().isoformat(),
    'severity': 10,
    'is_zeroday': True,
    'markov_probability': 0.0001,
    'original_request': {
        'process': 'powershell.exe',
        'pid': '1234',
        'syscall': 'NtCreateThreadEx'
    },
    'threats': [
        {'description': 'Privilege Escalation detected!'}
    ]
}

print("   - Sending test RASP email...")
send_rasp_alert_email(test_rasp_alert)

print("\n" + "=" * 60)
print("Test complete! Check your email!")
print("Note: Emails are only sent if SMTP_USER and SMTP_PASS are set in .env!")

