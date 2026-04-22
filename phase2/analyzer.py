# analyzer.py - Phase 2 Coordinator: Log Tailing & Orchestration
import json
import time
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
import asyncio
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from .rules import SecurityRules
from .ai_engine import AISecurityAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phase2_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class LogTailer:
    """Efficient log file tailing mechanism"""
    
    def __init__(self, log_file: str, state_file: str = 'analyzer_state.json'):
        self.log_file = log_file
        self.state_file = state_file
        self.last_position = 0
        self.load_state()
    
    def load_state(self):
        """Load last known position from state file"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    self.last_position = state.get('last_position', 0)
                    logger.info(f"Loaded state: position={self.last_position}")
            except Exception as e:
                logger.warning(f"Could not load state: {e}, starting from beginning")
                self.last_position = 0
    
    def save_state(self):
        """Save current position to state file"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump({
                    'last_position': self.last_position,
                    'last_update': datetime.now().isoformat()
                }, f)
        except Exception as e:
            logger.error(f"Could not save state: {e}")
    
    def get_new_lines(self) -> list:
        """Get only new lines since last read"""
        new_lines = []
        
        try:
            if not os.path.exists(self.log_file):
                logger.warning(f"Log file not found: {self.log_file}")
                return []
            
            file_size = os.path.getsize(self.log_file)
            
            # If file was rotated/truncated, reset position
            if file_size < self.last_position:
                logger.info("Log file was rotated, resetting position")
                self.last_position = 0
            
            with open(self.log_file, 'rb') as f:
                # Seek to last position
                f.seek(self.last_position)
                
                # Read new content
                new_content = f.read()
                self.last_position = f.tell()
                
                # Split by newline and parse
                if new_content:
                    lines = new_content.decode('utf-8', errors='ignore').split('\n')
                    
                    for line in lines:
                        line = line.strip()
                        if line:  # Skip empty lines
                            new_lines.append(line)
            
            if new_lines:
                logger.debug(f"Read {len(new_lines)} new lines from log")
        
        except Exception as e:
            logger.error(f"Error reading log file: {e}")
        
        return new_lines


class StatisticsTracker:
    """Track security analysis statistics"""
    
    def __init__(self, stats_file: str = 'statistics.json'):
        self.stats_file = stats_file
        self.stats = {
            'session_start': datetime.now().isoformat(),
            'total_requests_processed': 0,
            'requests_by_status': {
                'passed_tier1': 0,
                'flagged_tier1': 0,
                'analyzed_by_ai': 0,
                'threat_detected': 0
            },
            'threats_by_type': {},
            'top_attacking_ips': {}
        }
        self.load_stats()
    
    def load_stats(self):
        """Load existing statistics"""
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, 'r') as f:
                    self.stats = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load stats: {e}")
    
    def update(self, request_data: Dict, tier1_result: Dict, tier2_result: Optional[Dict] = None):
        """Update statistics based on analysis"""
        self.stats['total_requests_processed'] += 1
        
        # Track Tier 1 results
        if tier1_result['severity'] == 0:
            self.stats['requests_by_status']['passed_tier1'] += 1
        else:
            self.stats['requests_by_status']['flagged_tier1'] += 1
        
        # Track Tier 2 if used
        if tier2_result:
            self.stats['requests_by_status']['analyzed_by_ai'] += 1
            
            if tier2_result.get('severity', 0) >= 5:
                self.stats['requests_by_status']['threat_detected'] += 1
                
                threat_type = tier2_result.get('threat_type', 'UNKNOWN')
                self.stats['threats_by_type'][threat_type] = \
                    self.stats['threats_by_type'].get(threat_type, 0) + 1
        
        # Track attacking IPs
        client_ip = request_data.get('client_ip', 'unknown')
        if tier1_result['severity'] >= 4 or (tier2_result and tier2_result.get('severity', 0) >= 5):
            if client_ip not in self.stats['top_attacking_ips']:
                self.stats['top_attacking_ips'][client_ip] = {'count': 0, 'threats': []}
            
            self.stats['top_attacking_ips'][client_ip]['count'] += 1
            threat_type = tier2_result.get('threat_type', 'tier1') if tier2_result else 'tier1'
            self.stats['top_attacking_ips'][client_ip]['threats'].append(threat_type)
    
    def save(self):
        """Save statistics to file"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.stats, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Could not save stats: {e}")
    
    def get_summary(self) -> Dict:
        """Get statistics summary"""
        return self.stats


class SecurityAnalyzerPipeline:
    """Main orchestrator for Tier 1 + Tier 2 analysis"""
    
    def __init__(self, proxy_log: str = '../proxy.log', check_interval: int = 5,
                 alerts_file: str = 'phase2/alerts.json', state_file: str = 'phase2/analyzer_state.json',
                 stats_file: str = 'phase2/statistics.json'):
        self.proxy_log = proxy_log
        self.check_interval = check_interval
        self.alerts_file = alerts_file
        
        self.log_tailer = LogTailer(proxy_log, state_file=state_file)
        self.stats_tracker = StatisticsTracker(stats_file=stats_file)
        self.ai_analyzer = None  # Lazy load only if needed
        self.alerts = []
        
        # Load existing alerts from file (preserve history)
        self.load_alerts()
        
        logger.info(f"SecurityAnalyzerPipeline initialized (check_interval={check_interval}s)")
    
    def load_alerts(self):
        """Load existing alerts from file to preserve detection history"""
        if os.path.exists(self.alerts_file):
            try:
                with open(self.alerts_file, 'r') as f:
                    data = json.load(f)
                    self.alerts = data.get('alerts', [])
                    logger.info(f"Loaded {len(self.alerts)} existing alerts from {self.alerts_file}")
            except Exception as e:
                logger.warning(f"Could not load alerts: {e}, starting fresh")
                self.alerts = []
    
    def _init_ai_analyzer(self):
        """Lazy initialize AI analyzer (only if needed)"""
        if self.ai_analyzer is None:
            try:
                self.ai_analyzer = AISecurityAnalyzer()
                logger.info("AI analyzer initialized")
            except Exception as e:
                logger.error(f"Could not initialize AI analyzer: {e}")
    
    async def analyze_request(self, log_entry: Dict) -> Optional[Dict]:
        """
        Execute full analysis pipeline for a request
        Returns alert if threat detected, None otherwise
        
        Tier 1 Decision Logic:
        - Score > 7:   KNOWN_THREAT → Create alert immediately (skip Tier 2)
        - Score 4-7:   SUSPICIOUS → Send to Tier 2 for AI verification
        - Score < 4:   NORMAL → Ignore
        """
        # Tier 1: Rule-based filtering
        tier1_result = SecurityRules.analyze(log_entry)
        
        logger.debug(f"Tier 1 analysis: {log_entry.get('path')} -> severity={tier1_result['severity']}, requires_ai={tier1_result['requires_ai']}")
        
        tier2_result = None
        
        # Tier 2: AI analysis only for ambiguous cases (4-7 score)
        if tier1_result['requires_ai']:
            logger.info(f"Sending to Tier 2 (AI): {log_entry.get('path')} (Score {tier1_result['severity']} is ambiguous)")
            self._init_ai_analyzer()
            
            if self.ai_analyzer:
                tier2_result = await self.ai_analyzer.analyze(log_entry)
                logger.debug(f"Tier 2 result: severity={tier2_result.get('severity')}")
        else:
            if tier1_result['severity'] > 7:
                logger.debug(f"Tier 1 confidence high (score={tier1_result['severity']}) → Skipping Tier 2")
        
        # Update statistics
        self.stats_tracker.update(log_entry, tier1_result, tier2_result)
        
        # Determine if alert should be generated
        final_severity = tier2_result.get('severity', tier1_result['severity']) if tier2_result else tier1_result['severity']
        
        if final_severity >= 4:  # Alert threshold (lowered to catch all zero-day threats)
            alert = self._create_alert(log_entry, tier1_result, tier2_result, final_severity)
            logger.warning(f"THREAT DETECTED: {alert['threat_type']} (severity={final_severity})")
            return alert
        
        return None
    
    def _create_alert(self, log_entry: Dict, tier1_result: Dict, tier2_result: Optional[Dict], severity: int) -> Dict:
        """Create an alert entry"""
        return {
            'alert_id': len(self.alerts) + 1,
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'threat_type': tier2_result.get('threat_type', tier1_result['category']) if tier2_result else tier1_result['category'],
            'confidence': tier2_result.get('confidence', 0.5) if tier2_result else 0.0,
            'original_request': {
                'method': log_entry.get('method'),
                'path': log_entry.get('path'),
                'body_preview': log_entry.get('request_body_preview'),
                'client_ip': log_entry.get('client_ip'),
                'user_agent': log_entry.get('user_agent'),
                'response_status': log_entry.get('response_status')
            },
            'tier1_analysis': tier1_result,
            'tier2_analysis': tier2_result or {},
            'recommended_action': tier2_result.get('recommended_action') if tier2_result else 'investigate'
        }
    
    def save_alerts(self):
        """Save alerts to alerts.json"""
        try:
            with open(self.alerts_file, 'w') as f:
                json.dump({'alerts': self.alerts}, f, indent=2, default=str)
            logger.debug(f"Saved {len(self.alerts)} alerts to {self.alerts_file}")
        except Exception as e:
            logger.error(f"Could not save alerts: {e}")
    
    async def run_loop(self):
        """Main continuous monitoring loop"""
        logger.info("Starting analyzer loop...")
        loop_count = 0
        
        try:
            while True:
                loop_count += 1
                logger.debug(f"Analyzer loop iteration {loop_count}")
                
                # Get new log lines
                new_lines = self.log_tailer.get_new_lines()
                
                if new_lines:
                    logger.info(f"Processing {len(new_lines)} new log entries")
                    
                    for line in new_lines:
                        try:
                            log_entry = json.loads(line)
                            alert = await self.analyze_request(log_entry)
                            
                            if alert:
                                self.alerts.append(alert)
                                self.save_alerts()
                        
                        except json.JSONDecodeError:
                            logger.warning(f"Skipping malformed JSON: {line[:100]}")
                        except Exception as e:
                            logger.error(f"Error processing log entry: {e}")
                    
                    # Save state after processing
                    self.log_tailer.save_state()
                    self.stats_tracker.save()
                
                # Sleep before next check
                await asyncio.sleep(self.check_interval)
        
        except KeyboardInterrupt:
            logger.info("Analyzer stopped by user")
        except Exception as e:
            logger.error(f"Critical error in analyzer loop: {e}")
        finally:
            if self.ai_analyzer:
                await self.ai_analyzer.close()
            logger.info("Analyzer shutdown complete")
    
    def run(self):
        """Run analyzer (blocking)"""
        asyncio.run(self.run_loop())


# Entry point
if __name__ == '__main__':
    import sys
    
    # Get proxy log path from argument or use default
    log_path = sys.argv[1] if len(sys.argv) > 1 else '../proxy.log'
    
    logger.info(f"Starting Phase 2 Analyzer for: {log_path}")
    
    pipeline = SecurityAnalyzerPipeline(proxy_log=log_path, check_interval=5)
    pipeline.run()
