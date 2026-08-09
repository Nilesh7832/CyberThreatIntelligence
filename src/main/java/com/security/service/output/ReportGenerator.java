package com.security.service.output;

import com.security.dao.AuditLogDAO;
import com.security.dao.LoginDAO;
import com.security.dao.RiskScoreDAO;
import com.security.dao.ThreatDAO;
import com.security.model.LoginLog;
import com.security.model.RiskScore;
import com.security.model.ThreatAlert;
import com.security.utils.DateHelper;
import com.security.utils.Logger;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ReportGenerator - Generates full security reports.
 * Prints professional console report with:
 *   - Executive Summary
 *   - Login Analysis
 *   - Threat Summary
 *   - ML Risk Analysis
 *   - Top Attackers
 *   - Recommendations
 */
public class ReportGenerator {

    private static final Logger      log         = Logger.getInstance();
    private static final String      SOURCE      = "ReportGenerator";

    private final LoginDAO    loginDAO    = new LoginDAO();
    private final ThreatDAO   threatDAO   = new ThreatDAO();
    private final RiskScoreDAO riskDAO    = new RiskScoreDAO();
    private final AuditLogDAO auditDAO    = new AuditLogDAO();

    // ── Full Report ───────────────────────────────

    /**
     * Generates and prints the complete security report.
     * Call this as the main report entry point.
     */
    public void generateFullReport() {
        System.out.println("\n" + "═".repeat(55));
        System.out.println("   CYBER THREAT INTELLIGENCE - SECURITY REPORT");
        System.out.println("   Generated: " + DateHelper.now());
        System.out.println("═".repeat(55));

        printExecutiveSummary();
        printLoginAnalysis();
        printThreatSummary();
        printMLRiskAnalysis();
        printTopAttackers();
        printRecommendations();

        System.out.println("\n" + "═".repeat(55));
        System.out.println("   END OF REPORT");
        System.out.println("═".repeat(55) + "\n");

        log.info(SOURCE, "Full security report generated.");
    }

    // ── Executive Summary ─────────────────────────

    private void printExecutiveSummary() {
        List<LoginLog>    failed   = loginDAO.getFailedLogins();
        List<ThreatAlert> all      = threatDAO.getAllThreats();
        List<ThreatAlert> critical = threatDAO.getCriticalThreats();

        long foreign = failed.stream()
                .filter(l -> l.getLocation() != null
                        && !l.getLocation().equalsIgnoreCase("India"))
                .count();

        System.out.println("\n┌─ EXECUTIVE SUMMARY " + "─".repeat(34) + "┐");
        System.out.printf("│  %-30s : %-18d│%n",
                "Total Failed Logins", failed.size());
        System.out.printf("│  %-30s : %-18d│%n",
                "Foreign Login Attempts", foreign);
        System.out.printf("│  %-30s : %-18d│%n",
                "Total Threats Detected", all.size());
        System.out.printf("│  %-30s : %-18d│%n",
                "Critical Threats", critical.size());
        System.out.println("└" + "─".repeat(53) + "┘");
    }

    // ── Login Analysis ────────────────────────────

    private void printLoginAnalysis() {
        List<LoginLog> failed = loginDAO.getFailedLogins();

        System.out.println("\n▶ LOGIN ANALYSIS");
        System.out.println("  " + "─".repeat(50));

        // Group by location
        Map<String, Long> byLocation = failed.stream()
                .filter(l -> l.getLocation() != null)
                .collect(Collectors.groupingBy(
                        LoginLog::getLocation,
                        Collectors.counting()));

        System.out.println("  Failed logins by country:");
        byLocation.entrySet().stream()
                .sorted(Map.Entry.<String, Long>
                        comparingByValue().reversed())
                .limit(5)
                .forEach(e -> System.out.printf(
                        "    %-20s : %d%n",
                        e.getKey(), e.getValue()));

        // Off-hours logins
        long offHours = failed.stream()
                .filter(l -> {
                    int h = DateHelper.extractHour(l.getLoginTime());
                    return DateHelper.isSuspiciousHour(h);
                }).count();

        System.out.println("\n  Off-hours attempts (12am-5am): "
                + offHours);
    }

    // ── Threat Summary ────────────────────────────

    private void printThreatSummary() {
        List<ThreatAlert> threats = threatDAO.getAllThreats();

        System.out.println("\n▶ THREAT SUMMARY");
        System.out.println("  " + "─".repeat(50));

        // Group by type
        Map<String, Long> byType = threats.stream()
                .collect(Collectors.groupingBy(
                        ThreatAlert::getThreatType,
                        Collectors.counting()));

        byType.forEach((type, count) ->
                System.out.printf("  %-25s : %d%n", type, count));

        System.out.println();

        // Show each threat
        threats.forEach(t -> {
            String emoji = switch (t.getSeverity()) {
                case "CRITICAL" -> "🔴";
                case "HIGH"     -> "🟠";
                case "MEDIUM"   -> "🟡";
                default         -> "🟢";
            };
            System.out.printf(
                    "  %s [%-8s] %-22s → %s (%.0f/100)%n",
                    emoji, t.getSeverity(),
                    t.getThreatType(),
                    t.getSourceIp(),
                    t.getRiskScore());
        });
    }

    // ── ML Risk Analysis ──────────────────────────

    private void printMLRiskAnalysis() {
        List<RiskScore> scores = riskDAO.getAll();

        System.out.println("\n▶ ML RISK ANALYSIS (Weka)");
        System.out.println("  " + "─".repeat(50));

        if (scores.isEmpty()) {
            System.out.println("  No risk scores yet. Run scoring first.");
            return;
        }

        scores.stream().limit(10).forEach(rs ->
                System.out.printf(
                        "  %-16s │ %-8s │ Score: %5.1f │ ML: %s%n",
                        rs.getIpAddress(),
                        rs.getRiskLevel(),
                        rs.getTotalScore(),
                        rs.getMlPrediction()));
    }

    // ── Top Attackers ─────────────────────────────

    private void printTopAttackers() {
        List<LoginLog> failed = loginDAO.getFailedLogins();

        System.out.println("\n▶ TOP ATTACKERS");
        System.out.println("  " + "─".repeat(50));

        failed.stream()
                .collect(Collectors.groupingBy(
                        LoginLog::getIpAddress,
                        Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>
                        comparingByValue().reversed())
                .limit(5)
                .forEach(e -> System.out.printf(
                        "  🎯 %-18s → %d attempts%n",
                        e.getKey(), e.getValue()));
    }

    // ── Recommendations ───────────────────────────

    private void printRecommendations() {
        List<ThreatAlert> critical = threatDAO.getCriticalThreats();
        List<RiskScore>   highRisk = riskDAO.getCritical();

        System.out.println("\n▶ RECOMMENDATIONS");
        System.out.println("  " + "─".repeat(50));

        if (!critical.isEmpty()) {
            System.out.println("  🔴 URGENT ACTIONS REQUIRED:");
            System.out.println("     → Block " + critical.size()
                    + " critical IP(s) immediately");
            System.out.println("     → Enable 2-Factor Authentication");
            System.out.println("     → Review firewall rules");
            System.out.println("     → Check for data exfiltration");
        }

        if (!highRisk.isEmpty()) {
            System.out.println("\n  🟠 HIGH RISK ACTIONS:");
            System.out.println("     → Monitor " + highRisk.size()
                    + " high-risk IP(s)");
            System.out.println("     → Review access logs");
        }

        System.out.println("\n  🟢 GENERAL RECOMMENDATIONS:");
        System.out.println("     → Keep threat model updated");
        System.out.println("     → Schedule daily scans");
        System.out.println("     → Review audit logs weekly");
    }
}