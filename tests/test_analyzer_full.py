# test_analyzer_full.py - Test Phase 2 Full Analyzer Pipeline
"""
Tests for analyzer.py - Log tailing, orchestration, and alert generation
Run: python test_analyzer_full.py
"""

import json
import os
import sys
import tempfile
import asyncio
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from phase2.analyzer import SecurityAnalyzerPipeline, LogTailer, StatisticsTracker


class TestLogTailer:
    """Test LogTailer functionality"""
    
    @staticmethod
    def test_log_tailing():
        """Test log file tailing mechanism"""
        print("\n" + "="*70)
        print("TEST: LogTailer - Log File Tailing")
        print("="*70)
        
        # Create temporary log and state files
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, 'test.log')
            state_file = os.path.join(tmpdir, 'state.json')
            
            # Initialize tailer
            tailer = LogTailer(log_file, state_file)
            
            # Test 1: Empty log
            lines = tailer.get_new_lines()
            assert lines == [], f"Expected empty lines, got {lines}"
            print("✅ Test 1: Empty log returns no lines")
            
            # Test 2: Write first batch of logs
            log_entries = [
                {"timestamp": "2026-03-18T10:00:00", "method": "GET", "path": "api/test"},
                {"timestamp": "2026-03-18T10:00:01", "method": "POST", "path": "api/users"}
            ]
            
            with open(log_file, 'a') as f:
                for entry in log_entries:
                    f.write(json.dumps(entry) + '\n')
            
            lines = tailer.get_new_lines()
            assert len(lines) == 2, f"Expected 2 lines, got {len(lines)}"
            print(f"✅ Test 2: Read {len(lines)} lines from log")
            
            # Test 3: Save state
            tailer.save_state()
            assert os.path.exists(state_file), "State file not created"
            print("✅ Test 3: State file saved")
            
            # Test 4: Load state from new instance
            tailer2 = LogTailer(log_file, state_file)
            assert tailer2.last_position > 0, "Position not loaded"
            print(f"✅ Test 4: State loaded (position={tailer2.last_position})")
            
            # Test 5: Subsequent read returns no duplicates
            lines2 = tailer2.get_new_lines()
            assert lines2 == [], f"Expected no new lines, got {len(lines2)}"
            print("✅ Test 5: Subsequent read returns no duplicates")
            
            # Test 6: Write additional logs
            new_entry = {"timestamp": "2026-03-18T10:00:02", "method": "DELETE", "path": "api/data"}
            with open(log_file, 'a') as f:
                f.write(json.dumps(new_entry) + '\n')
            
            lines3 = tailer2.get_new_lines()
            assert len(lines3) == 1, f"Expected 1 new line, got {len(lines3)}"
            print(f"✅ Test 6: Detected {len(lines3)} new line(s)")
        
        print("\n✅ All LogTailer tests passed!")
        return True


class TestStatisticsTracker:
    """Test StatisticsTracker functionality"""
    
    @staticmethod
    def test_statistics():
        """Test statistics tracking"""
        print("\n" + "="*70)
        print("TEST: StatisticsTracker - Metrics Collection")
        print("="*70)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            stats_file = os.path.join(tmpdir, 'stats.json')
            tracker = StatisticsTracker(stats_file)
            
            # Test data
            normal_request = {
                'method': 'GET',
                'path': 'api/data',
                'client_ip': '127.0.0.1'
            }
            
            attack_request = {
                'method': 'POST',
                'path': 'api/users',
                'client_ip': '203.0.113.45'
            }
            
            tier1_normal = {'severity': 0}
            tier1_attack = {'severity': 8, 'category': 'KNOWN_THREAT'}
            tier2_attack = {'severity': 9, 'threat_type': 'SQLi', 'confidence': 0.95}
            
            # Test 1: Normal request passes Tier 1
            tracker.update(normal_request, tier1_normal)
            assert tracker.stats['total_requests_processed'] == 1
            assert tracker.stats['requests_by_status']['passed_tier1'] == 1
            print("✅ Test 1: Normal request tracked")
            
            # Test 2: Attack detected at Tier 1
            tracker.update(attack_request, tier1_attack, None)
            assert tracker.stats['total_requests_processed'] == 2
            assert tracker.stats['requests_by_status']['flagged_tier1'] == 1
            print("✅ Test 2: Tier 1 attack flagged")
            
            # Test 3: Attack analyzed by Tier 2
            tracker.update(attack_request, tier1_attack, tier2_attack)
            assert tracker.stats['total_requests_processed'] == 3
            assert tracker.stats['requests_by_status']['analyzed_by_ai'] == 1
            assert tracker.stats['requests_by_status']['threat_detected'] == 1
            assert 'SQLi' in tracker.stats['threats_by_type']
            print("✅ Test 3: Tier 2 detection tracked")
            
            # Test 4: IP tracking
            assert '203.0.113.45' in tracker.stats['top_attacking_ips']
            assert tracker.stats['top_attacking_ips']['203.0.113.45']['count'] >= 2
            print("✅ Test 4: Attacking IPs tracked")
            
            # Test 5: Save and verify
            tracker.save()
            assert os.path.exists(stats_file)
            with open(stats_file, 'r') as f:
                saved = json.load(f)
                assert saved['total_requests_processed'] == 3
            print("✅ Test 5: Statistics saved to file")
        
        print("\n✅ All StatisticsTracker tests passed!")
        return True


async def test_analyzer_pipeline():
    """Test full SecurityAnalyzerPipeline"""
    print("\n" + "="*70)
    print("TEST: SecurityAnalyzerPipeline - Full Orchestration")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, 'proxy.log')
        alerts_file = os.path.join(tmpdir, 'alerts.json')
        state_file = os.path.join(tmpdir, 'analyzer_state.json')
        stats_file = os.path.join(tmpdir, 'statistics.json')
        
        # Create test log entries
        test_logs = [
            {
                "timestamp": "2026-03-18T10:00:00",
                "method": "GET",
                "path": "health",
                "request_body_preview": "",
                "headers": {"user-agent": "Mozilla/5.0"},
                "client_ip": "127.0.0.1",
                "response_status": 200,
                "response_size": 398
            },
            {
                "timestamp": "2026-03-18T10:00:01",
                "method": "POST",
                "path": "api/users",
                "request_body_preview": "{'id': ' OR '1'='1'}",
                "headers": {"user-agent": "Mozilla/5.0"},
                "client_ip": "203.0.113.45",
                "response_status": 200,
                "response_size": 492
            }
        ]
        
        # Write test logs
        with open(log_file, 'a') as f:
            for log in test_logs:
                f.write(json.dumps(log) + '\n')
        
        print(f"✅ Test 1: Created test log with {len(test_logs)} entries")
        
        # Create pipeline with custom file paths for testing
        pipeline = SecurityAnalyzerPipeline(
            proxy_log=log_file,
            check_interval=1,
            alerts_file=alerts_file,
            state_file=state_file,
            stats_file=stats_file
        )
        
        # Run one loop iteration
        new_lines = pipeline.log_tailer.get_new_lines()
        assert len(new_lines) == len(test_logs), f"Expected {len(test_logs)} lines"
        print(f"✅ Test 2: Pipeline read {len(new_lines)} log entries")
        
        # Analyze each request
        analyzed_count = 0
        alerts_count = 0
        
        for line in new_lines:
            log_entry = json.loads(line)
            alert = await pipeline.analyze_request(log_entry)
            analyzed_count += 1
            
            if alert:
                alerts_count += 1
                pipeline.alerts.append(alert)
        
        print(f"✅ Test 3: Analyzed {analyzed_count} requests, detected {alerts_count} alerts")
        
        # Verify statistics
        assert pipeline.stats_tracker.stats['total_requests_processed'] == analyzed_count
        print(f"✅ Test 4: Statistics tracked ({analyzed_count} processed)")
        
        # Save and verify outputs
        pipeline.save_alerts()
        pipeline.log_tailer.save_state()
        pipeline.stats_tracker.save()
        
        assert os.path.exists(alerts_file), "alerts.json not created"
        assert os.path.exists(state_file), "analyzer_state.json not created"
        assert os.path.exists(stats_file), "statistics.json not created"
        print("✅ Test 5: All output files created")
        
        # Verify alert content
        if alerts_count > 0:
            with open(alerts_file, 'r') as f:
                alerts = json.load(f)
                assert len(alerts['alerts']) == alerts_count
                alert = alerts['alerts'][0]
                assert 'severity' in alert
                assert 'threat_type' in alert
                print(f"✅ Test 6: Alert validation passed (severity={alert['severity']})")
    
    print("\n✅ All SecurityAnalyzerPipeline tests passed!")
    return True


async def run_all_tests():
    """Run all tests"""
    print("\n" + "="*70)
    print("PHASE 2 - FULL ANALYZER PIPELINE TESTING")
    print("="*70)
    
    all_passed = True
    
    try:
        # Test LogTailer
        if not TestLogTailer.test_log_tailing():
            all_passed = False
    except Exception as e:
        print(f"❌ LogTailer test failed: {e}")
        all_passed = False
    
    try:
        # Test StatisticsTracker
        if not TestStatisticsTracker.test_statistics():
            all_passed = False
    except Exception as e:
        print(f"❌ StatisticsTracker test failed: {e}")
        all_passed = False
    
    try:
        # Test full pipeline
        if not await test_analyzer_pipeline():
            all_passed = False
    except Exception as e:
        print(f"❌ Pipeline test failed: {e}")
        all_passed = False
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    if all_passed:
        print("\n🎉 ALL ANALYZER TESTS PASSED!")
    else:
        print("\n❌ Some tests failed")
    
    return all_passed


if __name__ == '__main__':
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
