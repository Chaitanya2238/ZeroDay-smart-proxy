# rules.py - Tier 1: Heuristic Filter & Static Signatures
import re
import json
import math
from collections import Counter
from typing import Dict, Tuple
from urllib.parse import unquote, unquote_plus

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
            r"('\s*(?:OR|AND)\s*'(?:1|true)')",  # ' OR '1'='1
            r'("\s*(?:OR|AND)\s*"(?:1|true)")',  # " OR "1"="1
            r'(UNION\s+SELECT)',  # UNION SELECT injection
            r'(DROP\s+(?:TABLE|DATABASE))',  # DROP TABLE/DATABASE
            r'(INSERT\s+INTO)',  # INSERT INTO injection
            r'(DELETE\s+FROM)',  # DELETE FROM injection
            r'(EXEC\s*\(|EXECUTE\s*\()',  # EXEC() stored procedure
            r'(DECLARE\s+@)',  # DECLARE variable injection
            r'(;\s*(?:--|#))',  # SQL comment injection (-- or MySQL #)
            r'(UNION.*FROM)',  # UNION...FROM pattern
            r'(OR\s+1\s*=\s*1)',  # OR 1=1
            r'(%27\s*OR)',  # URL-encoded ' OR
        ],
        'xss_attack': [
            r'(<script[^>]*>)',  # <script> tags
            r'(javascript:)',  # javascript: protocol
            r'(onerror\s*=)',  # onerror event handler
            r'(onload\s*=)',  # onload event handler
            r'(onclick\s*=)',  # onclick event handler
            r'(alert\s*\()',  # alert() function call
            r'(<iframe[^>]*>)',  # iframe injection
            r'(eval\s*\()',  # eval() function
            r'(<img[^>]*on)',  # img tag with event handler
            r'(src\s*=\s*x)',  # img src=x (common XSS)
            r'(<svg[^>]*on)',  # svg with event handler
            r'(<body[^>]*on)',  # body tag with event handler
            r'(\$\{.*\})',  # Expression language injection
            r'(%3Cscript)',  # URL-encoded <script
            r'(&lt;script)',  # HTML-encoded <script
        ],
        'command_injection': [
            r'(;\s*(?:rm|cat|whoami|id|ls)\s+)',  # ; rm -rf or ; cat /
            r'(\|\s*(?:cat|grep|ls|nc))',  # | cat or | grep
            r'(\$\{[^}]*\})',  # ${} template injection
            r'(`[^`]*`)',  # Backtick command execution
            r'(\$\([^)]*\))',  # $() command substitution
            r'(whoami|id\s+|ls\s+-la|cat\s+/etc)',  # Common Unix commands
            r'(&&\s*(?:dir|type|tasklist|whoami))',  # && Windows commands
            r'(ping\s+&&)',  # ping && pattern specifically
            r'(&&\s*dir)',  # && dir pattern
            r'(&&\s*(?:type|tasklist|cmd))',  # && with other Windows commands
        ],
        'path_traversal': [
            r'(\.\./)',  # ../
            r'(\.\.\\)',  # ..\
            r'(%2e%2e/)',  # URL encoded ../
            r'(%2e%2e\\)',  # URL encoded ..\
            r'(file\s*=\s*\.\.)',  # file=.. parameter
            r'(path\s*=\s*\.\.)',  # path=.. parameter
            r'(/etc/passwd)',  # Linux system file
            r'(/etc/shadow)',  # Linux shadow file
            r'(\\windows\\)',  # Windows system path
            r'(\w:\\windows)',  # Windows drive path
            r'(/proc/)',  # Linux proc filesystem
            r'(/dev/)',  # Linux device files
        ],
        'ldap_injection': [
            r'(\$\{jndi:)',  # ${jndi: (Log4Shell pattern)
            r'(ldap://)',  # LDAP protocol
            r'(rmi://)',  # RMI protocol
            r'(\*\)\(uid)',  # LDAP escape sequence
            r'(\|\(uid)',  # LDAP OR injection
        ],
        'xxe_attack': [
            r'(<!DOCTYPE[^>]*\[)',  # External entity declaration
            r'(<!ENTITY.*SYSTEM)',  # SYSTEM entity reference
            r'(xml\s+version)',  # XML declaration with potential XXE
            r'(SYSTEM\s+"[^"]*")',  # SYSTEM keyword in XML
        ],
        'nosql_injection': [
            r'(\{\s*\$ne)',  # {"$ne": ""} MongoDB
            r'(\{\s*\$gt)',  # {"$gt": ""} MongoDB
            r'(\{\s*\$regex)',  # {"$regex": ""} MongoDB
            r'(\{\s*\$or)',  # {"$or": []} MongoDB
            r'(db\.[a-z]+\.(?:insert|find|update))',  # MongoDB patterns
            r'(\$where)',  # MongoDB $where operator
            r'(\$ne)',  # $ne operator anywhere (not just {"$ne")
            r'(\$gt|\$lt)',  # $gt or $lt operators
            r'(\$regex)',  # $regex operator
        ],
        'crlf_injection': [
            r'(%0d%0a)',  # URL encoded CRLF
            r'(%0d|%0a)',  # URL encoded CR or LF alone
            r'(\\r\\n)',  # Escaped CRLF
            r'(\r\n)',  # Actual CRLF
            r'(Set-Cookie:)',  # Header injection attempt
            r'(Content-Length:)',  # Trying to inject headers
        ],
        'file_inclusion': [
            r'(file://)',  # file:// protocol
            r'(php://)',  # php:// wrapper  
            r'(zip://)',  # zip:// wrapper
            r'(phar://)',  # phar:// wrapper
            r'(\.\./)',  # Directory traversal in file param (escaped dots)
            r'(/etc/passwd)',  # Etc passwd inclusion
            r'(download\?|file\s*=)',  # Download endpoint with file param
        ],
        'buffer_overflow': [
            r'(A{500,})',  # Long string of A's (500+ repetitions)
            r'(%x{20,})',  # Multiple format string specifiers
            r'([A-Z]{2000,})',  # Very long alphabetic string
            r'(\x41{100,})',  # Hex A's (100+)
        ],
        'authentication_bypass': [
            r'(bearer\s+[a-z0-9.]+)',  # Bearer token in headers
            r'(authorization:\s*bearer)',  # Suspicious auth header
            r'(Bearer\s+eyJ[A-Za-z0-9_-]+)',  # JWT token
            r'(eyJhbGc)',  # Base64 JWT header
            r'(bypass\s*=|admin\s*=)',  # Bypass/admin parameters
            r'(session_id\s*=.*|token\s*=)',  # Session manipulation
            r'(\+admin|\*admin)',  # Wildcard admin tricks
        ],
        'privilege_escalation': [
            r'(role\s*[=:]\s*(?:admin|root))',  # role assignment to admin
            r'(user_id|uid|user_role)',  # Privilege related params
            r'(is_admin|admin_flag|role)',  # Admin-related parameters
            r'(\broot\b|\badmin\b)',  # Common privilege keywords
        ],
        'scanner_detection': [
            r'(sqlmap|nikto|nmap|masscan|nessus|acunetix)',  # Scanner signatures
            r'(Burp|ZAP|Metasploit)',  # Penetration testing tools in UA
            r'(sqlmap/|nikto/|nmap/)',  # Scanner versions
            r'(w3af|OpenVAS|Qualys)',  # More scanners
        ],
    }
    
    # Anomaly Detection Heuristics
    ANOMALY_RULES = {
        'missing_user_agent': {
            'check': lambda req: not req.get('user_agent') or req.get('user_agent') == 'None',
            'score': 4,  # Increased from 3
            'reason': 'Missing or None User-Agent header (suspicious)'
        },
        'high_entropy_payload': {
            'check': lambda req: SecurityRules._check_high_entropy(req),
            'score': 6,
            'reason': 'High entropy in small payload (potential packed/encrypted zero-day)'
        },
        'suspicious_user_agent': {
            'check': lambda req: any(bot in (req.get('user_agent', '')).lower() 
                                     for bot in ['sqlmap', 'scanner', 'nikto', 'nmap', 'masscan']),
            'score': 6,  # Increased from 4
            'reason': 'Known vulnerability scanner detected in User-Agent'
        },
        'body_size_anomaly': {
            'check': lambda req: req.get('response_size', 0) > 1048576,  # 1MB
            'score': 5,  # Increased from 3
            'reason': 'Response size exceeds 1MB (potential data exfiltration)'
        },
        'health_endpoint_large_body': {
            'check': lambda req: req.get('path') == 'health' and req.get('response_size', 0) > 10000,
            'score': 6,  # Increased from 5
            'reason': 'Health check endpoint with abnormally large response'
        },
        'empty_path_with_post': {
            'check': lambda req: req.get('path') == '' and req.get('method') == 'POST',
            'score': 6,  # INCREASED from 4 - this is key anomaly!
            'reason': 'POST to root path with empty/minimal body (anomaly attack pattern)'
        },
        'slow_response': {
            'check': lambda req: req.get('response_time_ms', 0) > 5000,
            'score': 3,  # Increased from 2
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
    # WARNING: Minimal pass rules only for completely safe endpoints
    # User-Agent checks removed - attackers easily spoof browsers!
    PASS_RULES = {
        'health_check': {
            'check': lambda req: req.get('path') == 'health' and req.get('method') == 'GET',
            'reason': 'Standard health check endpoint'
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
        # URL-decode all parameters since proxy logs them encoded
        body_preview = unquote(request_data.get('request_body_preview', '')).lower()
        path = request_data.get('path', '').lower()
        headers_str = json.dumps(request_data.get('headers', {})).lower()
        user_agent = request_data.get('user_agent', '').lower()  # User-Agent for scanner detection
        query = unquote_plus(request_data.get('query', '')).lower()  # URL-decode query (unquote_plus converts + to space)
        
        # Combine all fields to search (including decoded query, headers, and user-agent)
        combined_search = f"{body_preview} {path} {headers_str} {user_agent} {query}"
        
        triggered_rules = []
        max_score = 0
        
        for attack_type, patterns in SecurityRules.STATIC_SIGNATURES.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, combined_search, re.IGNORECASE):
                        triggered_rules.append(f"{attack_type}:{pattern[:30]}...")
                        # Score based on attack type - be aggressive with known threats
                        if attack_type in ['sql_injection', 'xss_attack', 'command_injection']:
                            max_score = max(max_score, 9)  # Very high confidence
                        elif attack_type in ['ldap_injection', 'xxe_attack']:
                            max_score = max(max_score, 10)  # Absolute threat
                        elif attack_type in ['path_traversal', 'nosql_injection', 'crlf_injection']:
                            max_score = max(max_score, 9)  # High confidence - well-known attacks
                        elif attack_type in ['buffer_overflow', 'file_inclusion', 'authentication_bypass', 'privilege_escalation']:
                            max_score = max(max_score, 8)  # High confidence
                        elif attack_type in ['scanner_detection']:
                            max_score = max(max_score, 8)  # Known threat - scanners always alert immediately
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
        
        # Cap anomaly score at 7 (allows moderate anomalies to trigger Tier 2 more consistently)
        return min(total_score, 7), triggered_rules
    
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
    def calculate_shannon_entropy(data: str) -> float:
        """
        Calculates the Shannon entropy of a string to detect encrypted/packed payloads.
        """
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = Counter(data)
        for count in counts.values():
            p_x = count / length
            entropy += - p_x * math.log2(p_x)
        return entropy

    @staticmethod
    def _check_high_entropy(req: Dict) -> bool:
        """
        Helper method to safely evaluate payload entropy with size constraints.
        """
        body = req.get('request_body_preview', '')

        if not body:
            return False

        if len(body) >= 1024:
            return False

        return SecurityRules.calculate_shannon_entropy(body) > 7.5

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
