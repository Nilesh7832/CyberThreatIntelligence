-- =============================================
-- Sample Data - Testing ke liye
-- =============================================

-- USERS
INSERT INTO users (username, email, role, created_at) VALUES
                                                          ('alice', 'alice@company.com', 'ADMIN', '2024-01-01 09:00:00'),
                                                          ('bob', 'bob@company.com', 'USER', '2024-01-02 10:00:00'),
                                                          ('charlie', 'charlie@company.com', 'USER', '2024-01-03 11:00:00');

-- LOGIN LOGS - Normal logins
INSERT INTO login_logs (username, ip_address, login_time, success, failure_reason, location) VALUES
                                                                                                 ('alice', '192.168.1.10', '2024-06-01 09:00:00', 1, NULL, 'India'),
                                                                                                 ('bob', '192.168.1.11', '2024-06-01 09:05:00', 1, NULL, 'India');

-- LOGIN LOGS - Brute Force attack (same IP, baar baar fail)
INSERT INTO login_logs (username, ip_address, login_time, success, failure_reason, location) VALUES
                                                                                                 ('admin', '203.0.113.42', '2024-06-01 02:00:00', 0, 'WRONG_PASSWORD', 'China'),
                                                                                                 ('admin', '203.0.113.42', '2024-06-01 02:00:10', 0, 'WRONG_PASSWORD', 'China'),
                                                                                                 ('admin', '203.0.113.42', '2024-06-01 02:00:20', 0, 'WRONG_PASSWORD', 'China'),
                                                                                                 ('admin', '203.0.113.42', '2024-06-01 02:00:30', 0, 'WRONG_PASSWORD', 'China'),
                                                                                                 ('admin', '203.0.113.42', '2024-06-01 02:00:40', 0, 'WRONG_PASSWORD', 'China'),
                                                                                                 ('root',  '203.0.113.42', '2024-06-01 02:00:50', 0, 'WRONG_PASSWORD', 'China');

-- LOGIN LOGS - Suspicious foreign login
INSERT INTO login_logs (username, ip_address, login_time, success, failure_reason, location) VALUES
    ('alice', '41.57.106.22', '2024-06-01 03:30:00', 0, 'GEO_ANOMALY', 'Nigeria');

-- THREAT ALERTS
INSERT INTO threat_alerts (threat_type, source_ip, target_system, severity, detected_at, status, risk_score) VALUES
                                                                                                                 ('BRUTE_FORCE', '203.0.113.42', 'auth-server', 'CRITICAL', '2024-06-01 02:01:00', 'OPEN', 85.0),
                                                                                                                 ('GEO_ANOMALY', '41.57.106.22', 'auth-server', 'HIGH',     '2024-06-01 03:30:00', 'OPEN', 65.0),
                                                                                                                 ('PORT_SCAN',   '198.51.100.7', 'web-server',  'HIGH',     '2024-06-01 10:30:00', 'OPEN', 70.0),
                                                                                                                 ('MALWARE',     '10.0.0.55',    'db-server',   'CRITICAL', '2024-06-01 11:45:00', 'OPEN', 95.0);

-- RISK SCORES
INSERT INTO risk_scores (ip_address, score, fail_count, geo_risk, time_risk, speed_risk, calculated_at) VALUES
                                                                                                            ('203.0.113.42', 85.0, 6, 25.0, 20.0, 15.0, '2024-06-01 02:01:00'),
                                                                                                            ('41.57.106.22', 65.0, 1, 25.0, 20.0,  5.0, '2024-06-01 03:30:00'),
                                                                                                            ('198.51.100.7', 70.0, 0, 10.0,  5.0, 15.0, '2024-06-01 10:30:00');