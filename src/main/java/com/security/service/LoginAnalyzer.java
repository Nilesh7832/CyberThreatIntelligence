package com.security.service;

import com.security.config.AppConfig;
import com.security.dao.AuditLogDAO;
import com.security.dao.LoginDAO;
import com.security.model.AuditLog;
import com.security.model.LoginLog;
import com.security.utils.DateHelper;
import com.security.utils.Logger;
import com.security.utils.ValidationUtil;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * LoginAnalyzer - Analyzes login patterns for threats.
 * Detects:
 *   - Brute force attacks (many fails from one IP)
 *   - Credential stuffing (many usernames from one IP)
 *   - Geographic anomalies (foreign country logins)
 *   - Off-hours logins (suspicious time)
 */
public class LoginAnalyzer {

    private static final Logger    log      = Logger.getInstance();
    private static final String    SOURCE   = "LoginAnalyzer";

    private final LoginDAO    loginDAO    = new LoginDAO();
    private final AuditLogDAO auditLogDAO = new AuditLogDAO();
    private final AppConfig   config      = AppConfig.getInstance();

    // ── Brute Force Detection ─────────────────────

    /**
     * Checks if an IP has exceeded the brute-force threshold.
     * Threshold is read from config.properties.
     */
    public boolean isBruteForce(String ipAddress) {
        if (!ValidationUtil.isValidIp(ipAddress)) return false;

        int threshold = config.getBruteForceThreshold();
        int failCount = loginDAO.countFailedLoginsByIp(ipAddress);
        boolean detected = failCount >= threshold;

        if (detected) {
            log.security(SOURCE, "BRUTE FORCE detected from IP: "
                    + ipAddress + " | Fails: " + failCount
                    + " | Threshold: " + threshold);

            auditLogDAO.insert(new AuditLog(
                    0, DateHelper.now(), ipAddress,
                    AuditLog.Action.THREAT_DETECTED,
                    "auth-server",
                    "Brute force: " + failCount + " failed logins",
                    "SECURITY"
            ));
        }
        return detected;
    }

    // ── Credential Stuffing Detection ─────────────

    /**
     * Detects credential stuffing:
     * One IP trying many different usernames.
     * Threshold: 4+ distinct usernames = suspicious.
     */
    public boolean isCredentialStuffing(String ipAddress) {
        if (!ValidationUtil.isValidIp(ipAddress)) return false;

        List<LoginLog> logs = loginDAO.getLoginsByIp(ipAddress);

        long distinctUsers = logs.stream()
                .filter(l -> !l.isSuccess())
                .map(LoginLog::getUsername)
                .distinct()
                .count();

        boolean detected = distinctUsers >= 4;

        if (detected) {
            log.security(SOURCE,
                    "CREDENTIAL STUFFING from IP: " + ipAddress
                            + " | Distinct users tried: " + distinctUsers);
        }
        return detected;
    }

    // ── Geo Anomaly Detection ─────────────────────

    /**
     * Detects logins from high-risk or unusual countries.
     * Flags non-Indian IPs as potential anomalies.
     */
    public boolean isGeoAnomaly(String location) {
        if (ValidationUtil.isNullOrEmpty(location)) return false;
        boolean anomaly = !location.equalsIgnoreCase("India")
                && !location.equalsIgnoreCase("IN");
        if (anomaly) {
            log.security(SOURCE,
                    "GEO ANOMALY detected from: " + location);
        }
        return anomaly;
    }

    // ── Off-Hours Detection ───────────────────────

    /**
     * Flags logins that happen during suspicious hours.
     * Midnight to 5 AM = high risk window.
     */
    public boolean isOffHoursLogin(String loginTime) {
        if (ValidationUtil.isNullOrEmpty(loginTime)) return false;
        int hour = DateHelper.extractHour(loginTime);
        return DateHelper.isSuspiciousHour(hour);
    }

    // ── Full Analysis ─────────────────────────────

    /**
     * Runs complete analysis on all failed logins.
     * Prints a full suspicious login report.
     */
    public void analyzeAll() {
        List<LoginLog> failed = loginDAO.getFailedLogins();

        System.out.println("\n" + "=".repeat(50));
        System.out.println("  LOGIN ANALYSIS REPORT");
        System.out.println("=".repeat(50));
        System.out.println("  Total failed logins: " + failed.size());

        // Group by IP
        Map<String, List<LoginLog>> byIp = failed.stream()
                .collect(Collectors.groupingBy(LoginLog::getIpAddress));

        System.out.println("  Unique IPs involved: " + byIp.size());
        System.out.println("-".repeat(50));

        for (Map.Entry<String, List<LoginLog>> entry
                : byIp.entrySet()) {
            String ip   = entry.getKey();
            List<LoginLog> logs = entry.getValue();
            LoginLog first = logs.get(0);

            System.out.println("\n  IP       : " + ip);
            System.out.println("  Attempts : " + logs.size());
            System.out.println("  Location : " + first.getLocation());
            System.out.println("  First at : " + first.getLoginTime());

            // Run all checks
            if (isBruteForce(ip))
                System.out.println("  ⚠ BRUTE FORCE DETECTED");
            if (isCredentialStuffing(ip))
                System.out.println("  ⚠ CREDENTIAL STUFFING");
            if (isGeoAnomaly(first.getLocation()))
                System.out.println("  ⚠ GEO ANOMALY");
            if (isOffHoursLogin(first.getLoginTime()))
                System.out.println("  ⚠ OFF-HOURS LOGIN");
        }
        System.out.println("=".repeat(50) + "\n");
    }
}