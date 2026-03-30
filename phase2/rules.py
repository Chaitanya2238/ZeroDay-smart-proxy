# rules.py - Tier 1: Heuristic Filter & Static Signatures
import re
import json
from typing import Dict, Tuple

class SecurityRules:
    """
    Tier 1 Analysis: Fast regex-based threat detection
    Scores requests on a 0-10 scale to determine if they need AI analysis
    
    0-3: Normal traffic (ignore)
    4-6: Suspicious (pass to AI)
    7-10: Known threat (alert immediately)
    """
    
    # Static Signature Patterns (Known Attack Vectors)
    STATIC_SIGNATURES = {
        'sql_injection': [
            r"('\s*OR\s*'1'\s*=\s*'1)",  # ' OR '1'='1
            r'("\s*OR\s*"1"\s*=\s*"1)',  # " OR "1"="1
            r'(UNION\s+SELECT)',  # UNION SELECT injection
            r'(DROP\s+TABLE)',  # DROP TABLE attack
            r'(INSERT\s+INTO)',  # INSERT INTO injection
            r'(DELETE\s+FROM)',  # DELETE FROM injection
            r'(EXEC\s*\()',  # EXEC() stored procedure
            r'(DECLARE\s+@)',  # DECLARE variable injection
            r'(;.*--)',  # SQL comment injection
        ],
        'xss_attack': [
            r'(<script[^>]*>)',  # <script> tags
            r'(javascript:)',  # javascript: protocol
            r'(onerror\s*=)',  # onerror event handler
            r'(onload\s*=)',  # onload event handler
            r'(onclick\s*=)',  # onclick event handler
            r'(alert\s*\()',  # alert() function
            r'(<iframe[^>]*>)',  # iframe injection
            r'(eval\s*\()',  # eval() function
        ],
        'command_injection': [
            r'(;\s*rm\s+-rf)',  # ; rm -rf
            r'(\|\s*cat\s+)',  # | cat /
            r'(\$\{.*\})',  # ${} template injection
            r'(`[^`]*`)',  # Backtick command execution
            r'(\$\([^)]*\))',  # $() command substitution
            r'(whoami|id|ls\s+-la|cat\s+/etc)',  # Common commands
        ],
        'path_traversal': [
            r'(\.\./)',  # ../
            r'(\.\.\\)',  # ..\
            r'(%2e%2e)',  # URL encoded ../
            r'(/etc/passwd)',  # Linux system file
            r'(\\windows\\)',  # Windows system path
            r'(/proc/)',  # Linux proc filesystem
        ],
        'ldap_injection': [
            r'(\$\{jndi:)',  # ${jndi: (Log4Shell pattern)
            r'(ldap://)',  # LDAP protocol
            r'(rmi://)',  # RMI protocol
        ],
        'xxe_attack': [
            r'(<!DOCTYPE[^>]*\[)',  # External entity declaration
            r'(<!ENTITY.*SYSTEM)',  # SYSTEM entity reference
            r'(xml version)',  # XML declaration with potential XXE
        ],
        'nosql_injection': [
            r'(\{\s*\$ne)',  # {"$ne": ""} MongoDB
            r'(\{\s*\$gt)',  # {"$gt": ""} MongoDB
            r'(\{\s*\$regex)',  # {"$regex": ""} MongoDB
            r'(db\.[a-z]+\.(insert|find|update))',  # MongoDB patterns
        ],
        'crlf_injection': [
            r'(%0d%0a)',  # URL encoded CRLF
            r'(\\r\\n)',  # Escaped CRLF
            r'(\r\n)',  # Actual CRLF
            r'(Set-Cookie:)',  # Header injection
        ],
        'file_inclusion': [
            r'(file://)',  # file:// protocol
            r'(php://)',  # php:// wrapper
            r'(zip://)',  # zip:// wrapper
            r'(phar://)',  # phar:// wrapper
        ],
        'buffer_overflow': [
            r'(A{1000,})',  # Long string of A's
            r'(%x%x%x%x)',  # Format string
            r'(\x41{100,})',  # Hex A's
        ],
        'authentication_bypass': [
            r'(Bearer\s+eyJ[A-Za-z0-9_-]+)',  # JWT token
            r'(+admin|bypass|auth)',  # Common bypass keywords
            r'(session_id=.*|token=)',  # Session manipulation
        ],
        'privilege_escalation': [
            r'(role\s*[=:]\s*admin)',  # role assignment
            r'(user_id|uid|user_role)',  # Privilege related params
            r'(is_admin|admin_flag)',  # Admin flags
        ],
        'scanner_detection': [
            r'(sqlmap|nikto|nmap|masscan|nessus)',  # Scanner user agents
            r'(Burp|ZAP|Metasploit)',  # Penetration testing tools
        ],
    }
    
    # Anomaly Detection Heuristics
    ANOMALY_RULES = {
        'missing_user_agent': {
            'check': lambda req: not req.get('user_agent') or req.get('user_agent') == 'None',
            'score': 3,
            'reason': 'Missing or None User-Agent header (suspicious)'
        },
        'suspicious_user_agent': {
            'check': lambda req: any(bot in (req.get('user_agent', '')).lower() 
                                     for bot in ['sqlmap', 'scanner', 'nikto', 'nmap', 'masscan']),
            'score': 4,
            'reason': 'Known vulnerability scanner detected in User-Agent'
        },
        'body_size_anomaly': {
            'check': lambda req: req.get('response_size', 0) > 1048576,  # 1MB
            'score': 3,
            'reason': 'Response size exceeds 1MB (potential data exfiltration)'
        },
        'health_endpoint_large_body': {
            'check': lambda req: req.get('path') == 'health' and req.get('response_size', 0) > 10000,
            'score': 5,
            'reason': 'Health check endpoint with abnormally large response'
        },
        'empty_path_with_post': {
            'check': lambda req: req.get('path') == '' and req.get('method') == 'POST',
            'score': 4,
            'reason': 'POST to root path (suspicious request pattern)'
        },
        'slow_response': {
            'check': lambda req: req.get('response_time_ms', 0) > 5000,
            'score': 2,
            'reason': 'Response time > 5 seconds (potential DoS or backend issue)'
        },
        'high_error_rate': {
            'check': lambda req: req.get('response_status', 200) >= 500,
            'score': 2,
            'reason': 'Server error (5xx response)'
        },
        'forbidden_access': {
            'check': lambda req: req.get('response_status') == 403,
            'score': 1,
            'reason': 'Forbidden access (403) - may indicate reconnaissance'
        },
        'unauthorized_access': {
            'check': lambda req: req.get('response_status') == 401,
            'score': 2,
            'reason': 'Unauthorized access attempt (401)'
        },
    }
    
    # Pass Rules - Traffic to ignore (normal traffic)
    PASS_RULES = {
        'health_check': {
            'check': lambda req: req.get('path') == 'health' and req.get('method') == 'GET',
            'reason': 'Standard health check'
        },
        'browser_get_request': {
            'check': lambda req: req.get('method') == 'GET' 
                                and any(browser in (req.get('user_agent', '')).lower() 
                                       for browser in ['chrome', 'firefox', 'safari', 'edge']),
            'reason': 'Standard browser GET request'
        },
        'static_files': {
            'check': lambda req: any(req.get('path', '').endswith(ext) 
                                    for ext in ['.js', '.css', '.jpg', '.png', '.gif', '.ico']),
            'reason': 'Static file request (no analysis needed)'
        },
    }
    
    @staticmethod
    def check_static_signatures(request_data: Dict) -> Tuple[int, list]:
        """
        Check request against known attack patterns
        Returns: (severity_score, triggered_rules_list)
        """
        body_preview = request_data.get('request_body_preview', '').lower()
        path = request_data.get('path', '').lower()
        headers_str = json.dumps(request_data.get('headers', {})).lower()
        
        # Combine all fields to search
        combined_search = f"{body_preview} {path} {headers_str}"
        
        triggered_rules = []
        max_score = 0
        
        for attack_type, patterns in SecurityRules.STATIC_SIGNATURES.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, combined_search, re.IGNORECASE):
                        triggered_rules.append(f"{attack_type}:{pattern[:30]}...")
                        # Score based on attack type
                        if attack_type in ['sql_injection', 'xss_attack', 'command_injection']:
                            max_score = max(max_score, 8)
                        elif attack_type in ['ldap_injection', 'xxe_attack']:
                            max_score = max(max_score, 9)
                        elif attack_type in ['nosql_injection', 'crlf_injection', 'buffer_overflow']:
                            max_score = max(max_score, 7)
                        elif attack_type in ['file_inclusion', 'authentication_bypass', 'privilege_escalation']:
                            max_score = max(max_score, 7)
                        elif attack_type in ['scanner_detection']:
                            max_score = max(max_score, 5)
                        else:
                            max_score = max(max_score, 6)
                except re.error:
                    pass
        
        return max_score, triggered_rules
    
    @staticmethod
    def check_anomalies(request_data: Dict) -> Tuple[int, list]:
        """
        Check for anomalous behavior patterns
        Returns: (severity_score, triggered_rules_list)
        """
        triggered_rules = []
        total_score = 0
        
        for rule_name, rule_config in SecurityRules.ANOMALY_RULES.items():
            try:
                if rule_config['check'](request_data):
                    triggered_rules.append(rule_name)
                    total_score += rule_config['score']
            except Exception:
                pass
        
        # Cap anomaly score at 6 (to allow AI override for ambiguous cases)
        return min(total_score, 6), triggered_rules
    
    @staticmethod
    def check_pass_rules(request_data: Dict) -> Tuple[bool, str]:
        """
        Check if request matches "normal traffic" patterns
        Returns: (should_pass, reason)
        """
        for rule_name, rule_config in SecurityRules.PASS_RULES.items():
            try:
                if rule_config['check'](request_data):
                    return True, rule_config['reason']
            except Exception:
                pass
        
        return False, None
    
    @staticmethod
    def analyze(request_data: Dict) -> Dict:
        """
        Complete Tier 1 analysis pipeline
        Returns: Analysis result with severity score and reasoning
        """
        # Step 1: Check Pass Rules (save resources)
        should_pass, pass_reason = SecurityRules.check_pass_rules(request_data)
        if should_pass:
            return {
                'severity': 0,
                'category': 'PASS_RULE',
                'reason': pass_reason,
                'triggered_rules': [],
                'requires_ai': False
            }
        
        # Step 2: Check Static Signatures
        sig_score, sig_rules = SecurityRules.check_static_signatures(request_data)
        
        # Step 3: Check Anomalies
        anom_score, anom_rules = SecurityRules.check_anomalies(request_data)
        
        # Combine scores (max of both)
        final_score = max(sig_score, anom_score)
        all_rules = sig_rules + anom_rules
        
        # Determine if AI analysis is needed
        requires_ai = 4 <= final_score <= 7  # Ambiguous range
        
        return {
            'severity': final_score,
            'category': 'KNOWN_THREAT' if final_score >= 8 else 'SUSPICIOUS' if final_score >= 4 else 'NORMAL',
            'reason': f"Static signatures: {len(sig_rules)}, Anomalies: {len(anom_rules)}",
            'triggered_rules': all_rules,
            'signature_score': sig_score,
            'anomaly_score': anom_score,
            'requires_ai': requires_ai
        }


# Example usage
if __name__ == '__main__':
    test_request = {
        'method': 'POST',
        'path': 'api/users',
        'request_body_preview': "{'id': ' OR '1'='1', 'name': 'test'}",
        'headers': {'user-agent': 'Mozilla/5.0'},
        'response_status': 200,
        'response_size': 492,
        'response_time_ms': 45.2
    }
    
    result = SecurityRules.analyze(test_request)
    print(json.dumps(result, indent=2))
