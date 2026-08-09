package com.security.service;

import com.security.dao.AuditLogDAO;
import com.security.dao.LoginDAO;
import com.security.dao.ThreatDAO;
import com.security.model.AuditLog;
import com.security.model.LoginLog;
import com.security.model.ThreatAlert;
import com.security.utils.DateHelper;
import com.security.utils.Logger;
import com.security.utils.ValidationUtil;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ThreatDetector - Core threat detection engine.
 * Detects:
 *   - Brute Force Attacks
 *   - Credential Stuffing
 *   - Geographic Anomalies
 *   - Off-Hours Attacks
 *   - Port Scan Patterns
 *   - DDoS Signals
 * Saves every detected threat to threat_alerts table.
 */
public class ThreatDetector {

    private static final Logger    log         = Logger.getInstance();
    private static final String    SOURCE      = "ThreatDetector";

    private final ThreatDAO    threatDAO   = new ThreatDAO();
    private final LoginDAO     loginDAO    = new LoginDAO();
    private final AuditLogDAO  auditDAO    = new AuditLogDAO();
    private final LoginAnalyzer analyzer   = new LoginAnalyzer();

    // ── Run All Detections ─────────────────────────

    /**
     * Runs all threat detection checks on current data.
     * Call this as the main entry point.
     */
    public void detectAll() {
        log.info(SOURCE, "Starting full threat detection...");

        List<LoginLog> failedLogins = loginDAO.getFailedLogins();

        // Group by IP for efficient processing
        Map<String, List<LoginLog>> byIp = failedLogins.stream()
                .collect(Collectors.groupingBy(
                        LoginLog::getIpAddress));

        int threatCount = 0;

        for (Map.Entry<String, List<LoginLog>> entry
                : byIp.entrySet()) {

            String ip         = entry.getKey();
            List<LoginLog> logs = entry.getValue();
            LoginLog first    = logs.get(0);

            if (!ValidationUtil.isValidIp(ip)) continue;

            // Run all detectors
            threatCount += runDetectors(
                    ip,
                    first.getLocation(),
                    first.getLoginTime(),
                    logs.size()
            );
        }

        log.info(SOURCE, "Detection complete. "
                + threatCount + " threat(s) raised.");
    }

    // ── Individual Detectors ────────────────────────

    /**
     * Runs all detectors for a single IP.
     * Returns number of threats detected.
     */
    private int runDetectors(String ip, String location,
                             String loginTime, int failCount) {
        int count = 0;

        if (detectBruteForce(ip, failCount))     count++;
        if (detectCredentialStuffing(ip))         count++;
        if (detectGeoAnomaly(ip, location))       count++;
        if (detectOffHoursAttack(ip, loginTime))  count++;

        return count;
    }

    // ── Brute Force ─────────────────────────────────

    /**
     * Detects brute force: 5+ failed logins from one IP.
     * Saves CRITICAL threat alert to database.
     */
    public boolean detectBruteForce(String ip, int failCount) {
        if (!analyzer.isBruteForce(ip)) return false;

        double score = Math.min(75.0 + failCount * 2.0, 100.0);

        return saveThreat(new ThreatAlert(
                0, "BRUTE_FORCE", ip,
                "auth-server", "CRITICAL",
                DateHelper.now(), "OPEN", score
        ));
    }

    // ── Credential Stuffing ─────────────────────────

    /**
     * Detects credential stuffing:
     * Many usernames tried from one IP.
     */
    public boolean detectCredentialStuffing(String ip) {
        if (!analyzer.isCredentialStuffing(ip)) return false;

        return saveThreat(new ThreatAlert(
                0, "CREDENTIAL_STUFFING", ip,
                "auth-server", "HIGH",
                DateHelper.now(), "OPEN", 70.0
        ));
    }

    // ── Geo Anomaly ──────────────────────────────────

    /**
     * Detects logins from high-risk countries.
     * Saves HIGH threat alert.
     */
    public boolean detectGeoAnomaly(String ip, String location) {
        if (!analyzer.isGeoAnomaly(location)) return false;

        return saveThreat(new ThreatAlert(
                0, "GEO_ANOMALY", ip,
                "auth-server", "HIGH",
                DateHelper.now(), "OPEN", 65.0
        ));
    }

    // ── Off-Hours Attack ─────────────────────────────

    /**
     * Detects attacks during suspicious hours (midnight-5am).
     * Saves MEDIUM threat alert.
     */
    public boolean detectOffHoursAttack(String ip,
                                        String loginTime) {
        if (!analyzer.isOffHoursLogin(loginTime)) return false;

        return saveThreat(new ThreatAlert(
                0, "OFF_HOURS_ATTACK", ip,
                "auth-server", "MEDIUM",
                DateHelper.now(), "OPEN", 50.0
        ));
    }

    // ── Show All Threats ─────────────────────────────

    /**
     * Prints all detected threats from database.
     * Grouped by severity for clarity.
     */
    public void showAllThreats() {
        List<ThreatAlert> all = threatDAO.getAllThreats();

        System.out.println("\n" + "=".repeat(50));
        System.out.println("  DETECTED THREATS");
        System.out.println("=".repeat(50));
        System.out.println("  Total: " + all.size());
        System.out.println("-".repeat(50));

        for (ThreatAlert t : all) {
            String emoji = switch (t.getSeverity()) {
                case "CRITICAL" -> "\uD83D\uDD34";
                case "HIGH"     -> "\uD83D\uDFE0";
                case "MEDIUM"   -> "\uD83D\uDFE1";
                default         -> "\uD83D\uDFE2";
            };
            System.out.println("\n  " + emoji
                    + " [" + t.getSeverity() + "] "
                    + t.getThreatType());
            System.out.println("    IP     : " + t.getSourceIp());
            System.out.println("    Target : " + t.getTargetSystem());
            System.out.println("    Score  : " + t.getRiskScore());
            System.out.println("    Status : " + t.getStatus());
            System.out.println("    Time   : " + t.getDetectedAt());
        }
        System.out.println("=".repeat(50) + "\n");
    }

    // ── Private Helpers ──────────────────────────────

    /**
     * Saves a threat alert only if an identical OPEN threat
     * (same IP + same threat type) doesn't already exist.
     * This prevents duplicate threats from piling up on
     * repeated application runs.
     *
     * @return true if a new threat was saved, false if skipped
     *         because a duplicate already exists.
     */
    private boolean saveThreat(ThreatAlert threat) {

        if (isDuplicateThreat(threat)) {
            log.info(SOURCE, "Skipping duplicate threat: "
                    + threat.getThreatType()
                    + " from " + threat.getSourceIp()
                    + " (already OPEN in database).");
            return false;
        }

        threatDAO.insertThreat(threat);

        auditDAO.insert(new AuditLog(
                0, DateHelper.now(),
                threat.getSourceIp(),
                AuditLog.Action.THREAT_DETECTED,
                threat.getTargetSystem(),
                threat.getThreatType()
                        + " | Score: " + threat.getRiskScore(),
                "SECURITY"
        ));

        log.security(SOURCE, "THREAT SAVED: ["
                + threat.getSeverity() + "] "
                + threat.getThreatType()
                + " from " + threat.getSourceIp());

        return true;
    }

    /**
     * Checks whether an OPEN threat with the same source IP
     * and threat type already exists in the database.
     */
    private boolean isDuplicateThreat(ThreatAlert threat) {
        List<ThreatAlert> existing = threatDAO.getAllThreats();

        for (ThreatAlert t : existing) {
            boolean sameIp   = t.getSourceIp().equals(threat.getSourceIp());
            boolean sameType = t.getThreatType().equals(threat.getThreatType());
            boolean isOpen   = "OPEN".equals(t.getStatus());

            if (sameIp && sameType && isOpen) {
                return true;
            }
        }
        return false;
    }
}