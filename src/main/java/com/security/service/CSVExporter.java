package com.security.service.output;

import com.security.config.AppConfig;
import com.security.dao.LoginDAO;
import com.security.dao.RiskScoreDAO;
import com.security.dao.ThreatDAO;
import com.security.model.LoginLog;
import com.security.model.RiskScore;
import com.security.model.ThreatAlert;
import com.security.utils.DateHelper;
import com.security.utils.Logger;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/**
 * CSVExporter - Exports security data to CSV files.
 * Exports:
 *   - Threat alerts
 *   - Login logs
 *   - Risk scores
 * Files saved to reports/ directory.
 */
public class CSVExporter {

    private static final Logger    log    = Logger.getInstance();
    private static final String    SOURCE = "CSVExporter";

    private final AppConfig    config   = AppConfig.getInstance();
    private final ThreatDAO    threatDAO = new ThreatDAO();
    private final LoginDAO     loginDAO  = new LoginDAO();
    private final RiskScoreDAO riskDAO   = new RiskScoreDAO();

    // ── Export All ────────────────────────────────

    /**
     * Exports all data to CSV files.
     * Creates reports/ directory if needed.
     */
    public void exportAll() {
        createReportsDir();
        exportThreats();
        exportFailedLogins();
        exportRiskScores();
        log.info(SOURCE, "All CSV exports complete.");
    }

    // ── Export Threats ────────────────────────────

    /**
     * Exports threat_alerts table to CSV.
     * File: reports/threats_<date>.csv
     */
    public void exportThreats() {
        String path = config.getReportOutputPath()
                + "threats_"
                + DateHelper.todayForFilename() + ".csv";

        List<ThreatAlert> threats = threatDAO.getAllThreats();

        try (PrintWriter pw = new PrintWriter(
                new FileWriter(path))) {

            // Header
            pw.println("id,threat_type,source_ip,"
                    + "target_system,severity,"
                    + "detected_at,status,risk_score");

            // Rows
            for (ThreatAlert t : threats) {
                pw.printf("%d,%s,%s,%s,%s,%s,%s,%.1f%n",
                        t.getId(),
                        t.getThreatType(),
                        t.getSourceIp(),
                        t.getTargetSystem(),
                        t.getSeverity(),
                        t.getDetectedAt(),
                        t.getStatus(),
                        t.getRiskScore());
            }

            log.info(SOURCE, "Threats exported → "
                    + path + " (" + threats.size() + " rows)");
            System.out.println("  ✅ Threats CSV: " + path);

        } catch (IOException e) {
            log.error(SOURCE,
                    "exportThreats failed: " + e.getMessage());
        }
    }

    // ── Export Failed Logins ──────────────────────

    /**
     * Exports failed login records to CSV.
     * File: reports/failed_logins_<date>.csv
     */
    public void exportFailedLogins() {
        String path = config.getReportOutputPath()
                + "failed_logins_"
                + DateHelper.todayForFilename() + ".csv";

        List<LoginLog> logs = loginDAO.getFailedLogins();

        try (PrintWriter pw = new PrintWriter(
                new FileWriter(path))) {

            // Header
            pw.println("id,username,ip_address,"
                    + "login_time,failure_reason,location");

            // Rows
            for (LoginLog l : logs) {
                pw.printf("%d,%s,%s,%s,%s,%s%n",
                        l.getId(),
                        clean(l.getUsername()),
                        clean(l.getIpAddress()),
                        clean(l.getLoginTime()),
                        clean(l.getFailureReason()),
                        clean(l.getLocation()));
            }

            log.info(SOURCE, "Failed logins exported → "
                    + path + " (" + logs.size() + " rows)");
            System.out.println("  ✅ Failed Logins CSV: " + path);

        } catch (IOException e) {
            log.error(SOURCE,
                    "exportFailedLogins failed: " + e.getMessage());
        }
    }

    // ── Export Risk Scores ────────────────────────

    /**
     * Exports ML risk scores to CSV.
     * File: reports/risk_scores_<date>.csv
     */
    public void exportRiskScores() {
        String path = config.getReportOutputPath()
                + "risk_scores_"
                + DateHelper.todayForFilename() + ".csv";

        List<RiskScore> scores = riskDAO.getAll();

        try (PrintWriter pw = new PrintWriter(
                new FileWriter(path))) {

            // Header
            pw.println("id,ip_address,total_score,"
                    + "risk_level,fail_count,"
                    + "geo_risk,time_risk,speed_risk,"
                    + "ml_prediction,calculated_at");

            // Rows
            for (RiskScore rs : scores) {
                pw.printf("%d,%s,%.1f,%s,%d,"
                                + "%.1f,%.1f,%.1f,%s,%s%n",
                        rs.getId(),
                        rs.getIpAddress(),
                        rs.getTotalScore(),
                        rs.getRiskLevel(),
                        rs.getFailCount(),
                        rs.getGeoRisk(),
                        rs.getTimeRisk(),
                        rs.getSpeedRisk(),
                        rs.getMlPrediction(),
                        rs.getCalculatedAt());
            }

            log.info(SOURCE, "Risk scores exported → "
                    + path + " (" + scores.size() + " rows)");
            System.out.println("  ✅ Risk Scores CSV: " + path);

        } catch (IOException e) {
            log.error(SOURCE,
                    "exportRiskScores failed: " + e.getMessage());
        }
    }

    // ── Private Helpers ───────────────────────────

    /** Creates reports directory if it doesn't exist. */
    private void createReportsDir() {
        try {
            Files.createDirectories(
                    Paths.get(config.getReportOutputPath()));
        } catch (IOException e) {
            log.error(SOURCE,
                    "Could not create reports dir: "
                            + e.getMessage());
        }
    }

    /** Cleans a value for CSV output (handles nulls). */
    private String clean(String value) {
        if (value == null) return "";
        // Escape commas in values
        return value.contains(",")
                ? "\"" + value + "\""
                : value;
    }
}