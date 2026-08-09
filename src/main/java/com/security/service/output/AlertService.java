package com.security.service.output;

import com.security.config.AppConfig;
import com.security.model.ThreatAlert;
import com.security.utils.DateHelper;
import com.security.utils.Logger;

import java.util.List;

/**
 * AlertService - Sends alerts for detected threats.
 * Supports:
 *   - Console alerts (always on)
 *   - Email alerts (configurable)
 * Add more channels (Slack, SMS) here in future.
 */
public class AlertService {

    private static final Logger    log    = Logger.getInstance();
    private static final String    SOURCE = "AlertService";
    private final AppConfig config = AppConfig.getInstance();

    // ── Single Threat Alert ───────────────────────

    /**
     * Sends an alert for a single detected threat.
     * Routes to console and/or email based on config.
     */
    public void sendAlert(ThreatAlert threat) {
        if (config.getBoolean("alert.console.enabled", true)) {
            consoleAlert(threat);
        }
        if (config.isEmailAlertEnabled()) {
            emailAlert(threat);
        }
    }

    // ── Batch Alerts ──────────────────────────────

    /**
     * Sends alerts for a list of threats.
     * Only alerts on HIGH and CRITICAL severity.
     */
    public void sendBatchAlerts(List<ThreatAlert> threats) {
        long serious = threats.stream()
                .filter(t -> t.getSeverity().equals("CRITICAL")
                        || t.getSeverity().equals("HIGH"))
                .count();

        log.info(SOURCE, "Sending alerts for "
                + serious + " serious threat(s)...");

        threats.stream()
                .filter(t -> t.getSeverity().equals("CRITICAL")
                        || t.getSeverity().equals("HIGH"))
                .forEach(this::sendAlert);
    }

    // ── Console Alert ─────────────────────────────

    /**
     * Prints a formatted alert to the console.
     * Always enabled — zero dependencies.
     */
    private void consoleAlert(ThreatAlert threat) {
        String border = "!".repeat(52);
        String emoji  = getEmoji(threat.getSeverity());

        System.out.println("\n" + border);
        System.out.println("  " + emoji
                + " SECURITY ALERT - "
                + threat.getSeverity());
        System.out.println(border);
        System.out.println("  Type    : " + threat.getThreatType());
        System.out.println("  Source  : " + threat.getSourceIp());
        System.out.println("  Target  : " + threat.getTargetSystem());
        System.out.println("  Score   : " + threat.getRiskScore()
                + "/100");
        System.out.println("  Time    : " + threat.getDetectedAt());
        System.out.println("  Status  : " + threat.getStatus());
        System.out.println(border + "\n");

        log.security(SOURCE, "ALERT SENT: ["
                + threat.getSeverity() + "] "
                + threat.getThreatType()
                + " from " + threat.getSourceIp());
    }

    // ── Email Alert ───────────────────────────────

    /**
     * Sends an email alert via SMTP.
     * Configure in config.properties to enable.
     * Currently logs intent — add JavaMail impl if needed.
     */
    private void emailAlert(ThreatAlert threat) {
        String to      = config.get("alert.email.to");
        String subject = "[CTI ALERT] "
                + threat.getSeverity()
                + " - " + threat.getThreatType();
        String body    = buildEmailBody(threat);

        // Log the email intent
        log.info(SOURCE, "Email alert queued → To: "
                + to + " | Subject: " + subject);

        // TODO: Uncomment below when JavaMail is configured
        // sendViaSMTP(to, subject, body);
        System.out.println("[Email Alert] Would send to: " + to);
        System.out.println("[Email Alert] Subject: " + subject);
    }

    // ── Summary Alert ─────────────────────────────

    /**
     * Prints a daily summary alert to console.
     * Call this at end of each detection cycle.
     */
    public void sendDailySummary(int totalThreats,
                                 int critical,
                                 int high,
                                 int blocked) {
        System.out.println("\n" + "=".repeat(52));
        System.out.println("  📊 DAILY SECURITY SUMMARY - "
                + DateHelper.todayForFilename());
        System.out.println("=".repeat(52));
        System.out.printf("  Total Threats  : %d%n", totalThreats);
        System.out.printf("  Critical       : %d 🔴%n", critical);
        System.out.printf("  High           : %d 🟠%n", high);
        System.out.printf("  IPs Blocked    : %d 🚫%n", blocked);
        System.out.println("=".repeat(52) + "\n");

        log.info(SOURCE, "Daily summary: threats="
                + totalThreats + ", critical=" + critical
                + ", blocked=" + blocked);
    }

    // ── Private Helpers ───────────────────────────

    private String getEmoji(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "🔴";
            case "HIGH"     -> "🟠";
            case "MEDIUM"   -> "🟡";
            default         -> "🟢";
        };
    }

    private String buildEmailBody(ThreatAlert threat) {
        return String.format("""
            CYBER THREAT INTELLIGENCE ALERT
            ================================
            Type     : %s
            Severity : %s
            Source IP: %s
            Target   : %s
            Score    : %.1f / 100
            Time     : %s
            Status   : %s
            ================================
            Action Required: Review and respond immediately.
            """,
                threat.getThreatType(),
                threat.getSeverity(),
                threat.getSourceIp(),
                threat.getTargetSystem(),
                threat.getRiskScore(),
                threat.getDetectedAt(),
                threat.getStatus()
        );
    }
}