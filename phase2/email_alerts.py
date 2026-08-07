
# email_alerts.py - Email alert functionality for zero-day/anomaly detection
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import os
import logging
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)

# Email configuration
ADMIN_EMAIL = "guptadivya958@gmail.com"

# Default email settings (using Gmail as an example - note: you may need app-specific password)
# You can modify these via .env variables if needed!
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").replace(" ", "").strip()  # Remove spaces from app password

# Track last email sent to avoid spamming (rate limiting)
_last_sent_at = None
_email_cooldown = 60  # seconds - only send one email per minute at most
_last_alert_ids = set()


def send_threat_email(alert: dict):
    """
    Send an email alert to admin when a threat or zero-day attack is detected
    """
    global _last_sent_at, _last_alert_ids
    
    # Check if this alert has already been sent
    alert_id = alert.get('alert_id')
    if alert_id in _last_alert_ids:
        logger.debug(f"Alert {alert_id} already sent, skipping email")
        return
    
    # Check cooldown to avoid spamming
    now = datetime.now()
    if _last_sent_at and (now - _last_sent_at).total_seconds() < _email_cooldown:
        logger.debug("Email cooldown active, skipping email")
        return
    
    # Check if email credentials are set
    if not SMTP_USER or not SMTP_PASS:
        logger.warning("Email credentials not set! Please set SMTP_USER and SMTP_PASS in .env to receive email alerts.")
        return
    
    try:
        # Create email content
        subject = f"[URGENT] Security Alert: {alert.get('threat_type', 'THREAT DETECTED')}"
        
        body = f"""
==============================================
            SECURITY ALERT - INVESTIGATION REQUIRED
==============================================

Time: {alert.get('timestamp', datetime.now().isoformat())}
Threat Type: {alert.get('threat_type', 'UNKNOWN')}
Severity: {alert.get('severity', 0)}/10
Alert ID: {alert_id}
Is Zero-Day: {alert.get('is_zeroday', 'No')}

==============================================
                   DETAILS
==============================================

"""
        
        # Add original request details
        if 'original_request' in alert:
            req = alert['original_request']
            body += f"""
Request Method: {req.get('method', 'N/A')}
Request Path: {req.get('path', 'N/A')}
Client IP: {req.get('client_ip', 'N/A')}
User Agent: {req.get('user_agent', 'N/A')}
Body Preview: {req.get('body_preview', 'N/A')}
"""
        
        # Add analysis details
        body += f"""
==============================================
              ANALYSIS SUMMARY
==============================================
Confidence: {alert.get('confidence', 0) * 100:.1f}%
Recommended Action: {alert.get('recommended_action', 'investigate')}
"""
        
        if 'tier1_analysis' in alert:
            tier1 = alert['tier1_analysis']
            body += f"""
Tier 1 (Rules) Analysis:
  - Category: {tier1.get('category', 'N/A')}
  - Severity: {tier1.get('severity', 0)}
  - Reason: {tier1.get('reason', 'N/A')}
"""
        
        if 'tier2_analysis' in alert:
            tier2 = alert['tier2_analysis']
            if tier2:
                body += f"""
Tier 2 (AI/ML) Analysis:
  - Category: {tier2.get('threat_type', 'N/A')}
  - Confidence: {tier2.get('confidence', 0) * 100:.1f}%
  - Reasoning: {tier2.get('reasoning', 'N/A')}
"""
        
        body += f"""
==============================================
              NEXT STEPS
==============================================
1. Review the alert in the dashboard
2. Investigate the suspicious activity
3. Take appropriate action (block IP, investigate process, etc.)

==============================================
        This is an automated alert - do not reply
==============================================
"""
        
        # Set up email
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            text = msg.as_string()
            server.sendmail(SMTP_USER, ADMIN_EMAIL, text)
        
        logger.info(f"Email alert sent successfully to {ADMIN_EMAIL} for alert {alert_id}!")
        
        # Update tracking
        _last_sent_at = now
        _last_alert_ids.add(alert_id)
        # Keep last 100 alert IDs to avoid duplicates
        if len(_last_alert_ids) > 100:
            _last_alert_ids = set(list(_last_alert_ids)[-50:])
        
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")


def send_rasp_alert_email(alert: dict):
    """
    Send an email alert specifically for RASP (Runtime Application Self-Protection) zero-day threats
    """
    global _last_sent_at, _last_alert_ids
    
    alert_id = alert.get('alert_id')
    if alert_id in _last_alert_ids:
        logger.debug(f"RASP alert {alert_id} already sent, skipping email")
        return
    
    now = datetime.now()
    if _last_sent_at and (now - _last_sent_at).total_seconds() < _email_cooldown:
        logger.debug("Email cooldown active, skipping email")
        return
    
    if not SMTP_USER or not SMTP_PASS:
        logger.warning("Email credentials not set! Please set SMTP_USER and SMTP_PASS in .env to receive RASP alerts.")
        return
    
    try:
        subject = f"[CRITICAL] RASP ALERT: Zero-Day Privilege Escalation Detected!"
        
        body = f"""
==============================================
       CRITICAL RASP ALERT - IMMEDIATE ACTION
==============================================

Time: {alert.get('timestamp', datetime.now().isoformat())}
Alert ID: {alert_id}
Severity: {alert.get('severity', 0)}/10
Is Zero-Day: YES

==============================================
               RASP DETAILS
==============================================

"""
        
        if 'original_request' in alert:
            req = alert['original_request']
            body += f"""
Process Name: {req.get('process', 'N/A')}
Process PID: {req.get('pid', 'N/A')}
System Call: {req.get('syscall', 'N/A')}
"""
        
        body += f"""
Markov Probability: {alert.get('markov_probability', 0.0)}
Threats: {', '.join([t.get('description', '') for t in alert.get('threats', [])])}
"""
        
        body += f"""
==============================================
              NEXT STEPS
==============================================
1. Check the system immediately for suspicious activity
2. Review the RASP monitoring dashboard
3. Isolate the affected process/system if needed
4. Investigate the privilege escalation attempt

==============================================
        This is an automated alert - do not reply
==============================================
"""
        
        # Set up email
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            text = msg.as_string()
            server.sendmail(SMTP_USER, ADMIN_EMAIL, text)
        
        logger.info(f"RASP Email alert sent successfully to {ADMIN_EMAIL}!")
        
        _last_sent_at = now
        _last_alert_ids.add(alert_id)
        if len(_last_alert_ids) > 100:
            _last_alert_ids = set(list(_last_alert_ids)[-50:])
        
    except Exception as e:
        logger.error(f"Failed to send RASP email alert: {e}")

