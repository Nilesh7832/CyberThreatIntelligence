package com.security;

import com.security.config.AppConfig;
import com.security.config.DBConnection;
import com.security.dao.ThreatDAO;
import com.security.model.AuditLog;
import com.security.model.ThreatAlert;
import com.security.dao.AuditLogDAO;
import com.security.service.LoginAnalyzer;
import com.security.service.RiskScorer;
import com.security.service.ThreatDetector;
import com.security.service.detection.IPBlacklistService;
import com.security.service.ml.ModelEvaluator;
import com.security.service.ml.ModelPersistence;
import com.security.service.ml.ModelTrainer;
import com.security.service.output.AlertService;
import com.security.service.output.CSVExporter;
import com.security.service.output.ReportGenerator;
import com.security.utils.DateHelper;
import com.security.utils.Logger;
import com.security.service.output.DashboardGenerator;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;

/**
 * Main - Entry point for the CTI Framework.
 *
 * Execution order:
 *   1. Initialize database
 *   2. Load seed data
 *   3. Train ML model
 *   4. Evaluate ML model
 *   5. Run threat detection
 *   6. Score all IPs
 *   7. Auto-block critical IPs
 *   8. Generate report
 *   9. Export CSV
 *  10. Show summary
 */
public class Main {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "Main";

    public static void main(String[] args) {

        printBanner();

        // ── Step 1: Initialize Database ──────────
        log.info(SOURCE, "Step 1: Initializing database...");
        initDatabase();

        // ── Step 2: Load Sample Data ──────────────
        log.info(SOURCE, "Step 2: Loading sample data...");
        loadSampleData();

        // ── Step 3: Train ML Model ────────────────
        log.info(SOURCE, "Step 3: Training ML model...");
        ModelTrainer    trainer     = new ModelTrainer();
        ModelPersistence persistence = new ModelPersistence();
        ModelEvaluator  evaluator   = new ModelEvaluator();

        boolean trained = trainer.trainAll();

        if (trained) {
            // Evaluate both models
            evaluator.evaluate(
                    trainer.getRandomForest(),
                    trainer.getTrainingData(),
                    "Random Forest");

            evaluator.evaluate(
                    trainer.getDecisionTree(),
                    trainer.getTrainingData(),
                    "J48 Decision Tree");

            // Save best model (Random Forest)
            persistence.savePrimaryModel(
                    trainer.getRandomForest());
            persistence.saveDecisionTree(
                    trainer.getDecisionTree());

            log.info(SOURCE, "Models saved successfully.");
        } else {
            log.warn(SOURCE,
                    "Training failed. Using rule-based fallback.");
        }

        // ── Step 4: Login Analysis ────────────────
        log.info(SOURCE, "Step 4: Analyzing logins...");
        LoginAnalyzer analyzer = new LoginAnalyzer();
        analyzer.analyzeAll();

        // ── Step 5: Threat Detection ──────────────
        log.info(SOURCE, "Step 5: Detecting threats...");
        ThreatDetector detector = new ThreatDetector();
        detector.detectAll();
        detector.showAllThreats();

        // ── Step 6: ML Risk Scoring ───────────────
        log.info(SOURCE, "Step 6: Scoring IPs with ML...");
        RiskScorer scorer = new RiskScorer();
        scoreAllIps(scorer);

        // ── Step 7: Auto-block Critical IPs ──────
        log.info(SOURCE, "Step 7: Auto-blocking critical IPs...");
        autoBlockCritical();

        // ── Step 8: Generate Report ───────────────
        log.info(SOURCE, "Step 8: Generating report...");
        ReportGenerator reporter = new ReportGenerator();
        reporter.generateFullReport();

        // ── Step 9: Export CSV ────────────────────
        log.info(SOURCE, "Step 9: Exporting CSV files...");
        System.out.println("\n[CSV Export]");
        CSVExporter exporter = new CSVExporter();
        exporter.exportAll();
        // ── Step 9.5: Generate Dashboard ──────────
        log.info(SOURCE, "Generating HTML dashboard...");
        System.out.println("\n[Dashboard]");
        DashboardGenerator dashboard = new DashboardGenerator();
        dashboard.generate();

        // ── Step 10: Send Alerts ──────────────────
        log.info(SOURCE, "Step 10: Sending alerts...");
        sendAlerts();

        // ── Done ──────────────────────────────────
        printDone();

        // Record system stop
        new AuditLogDAO().insert(new AuditLog(
                0, DateHelper.now(), "SYSTEM",
                AuditLog.Action.SYSTEM_STOP,
                "CTI Framework", "Run complete", "INFO"
        ));

        DBConnection.closeConnection();
    }

    // ── Database Init ─────────────────────────────

    private static void initDatabase() {
        try {
            Connection conn = DBConnection.getConnection();
            // Run schema
            java.io.InputStream in =
                    Main.class.getResourceAsStream("/schema.sql");
            String sql = new String(in.readAllBytes());
            Statement st = conn.createStatement();
            for (String s : sql.split(";")) {
                if (!s.isBlank()) st.execute(s.trim());
            }
            log.info(SOURCE, "Database initialized.");

            // Record system start
            new AuditLogDAO().insert(new AuditLog(
                    0, DateHelper.now(), "SYSTEM",
                    AuditLog.Action.SYSTEM_START,
                    "CTI Framework",
                    "Framework started", "INFO"
            ));

        } catch (Exception e) {
            log.error(SOURCE,
                    "DB init failed: " + e.getMessage());
        }
    }

    // ── Load Sample Data ──────────────────────────

    private static void loadSampleData() {
        try {
            Connection conn = DBConnection.getConnection();

            // Check if data already exists — avoid duplicate inserts
            Statement checkSt = conn.createStatement();
            java.sql.ResultSet rs = checkSt.executeQuery(
                    "SELECT COUNT(*) AS cnt FROM threat_alerts");
            boolean alreadyLoaded = false;
            if (rs.next() && rs.getInt("cnt") > 0) {
                alreadyLoaded = true;
            }
            rs.close();

            if (alreadyLoaded) {
                log.info(SOURCE,
                        "Sample data already present. Skipping load.");
                return;
            }

            java.io.InputStream in =
                    Main.class.getResourceAsStream("/sample_data.sql");
            String sql = new String(in.readAllBytes());
            Statement st = conn.createStatement();
            for (String s : sql.split(";")) {
                if (!s.isBlank()) {
                    try { st.execute(s.trim()); }
                    catch (Exception ignored) {}
                }
            }
            log.info(SOURCE, "Sample data loaded.");
        } catch (Exception e) {
            log.warn(SOURCE,
                    "Sample data load: " + e.getMessage());
        }
    }

    // ── Score All IPs ─────────────────────────────

    private static void scoreAllIps(RiskScorer scorer) {
        String[][] testIps = {
                {"203.0.113.42",  "China",   "2024-06-01 02:00:00"},
                {"185.220.101.3", "Russia",  "2024-06-01 12:00:00"},
                {"41.57.106.22",  "Nigeria", "2024-06-01 03:30:00"},
                {"198.51.100.7",  "Unknown", "2024-06-01 10:30:00"},
                {"192.168.1.10",  "India",   "2024-06-01 09:00:00"},
        };

        System.out.println("\n[ML Risk Scoring]");
        for (String[] ip : testIps) {
            scorer.scoreIp(ip[0], ip[1], ip[2]);
        }
    }

    // ── Auto Block ────────────────────────────────

    private static void autoBlockCritical() {
        ThreatDAO threatDAO = new ThreatDAO();
        IPBlacklistService blacklist = new IPBlacklistService();

        List<ThreatAlert> critical =
                threatDAO.getCriticalThreats();

        critical.stream()
                .map(ThreatAlert::getSourceIp)
                .distinct()
                .forEach(ip -> blacklist.blockIp(
                        ip,
                        "Auto-blocked: CRITICAL threat",
                        "SYSTEM"));

        blacklist.printBlacklist();
    }

    // ── Send Alerts ───────────────────────────────

    private static void sendAlerts() {
        ThreatDAO    threatDAO = new ThreatDAO();
        AlertService alerts    = new AlertService();

        List<ThreatAlert> threats =
                threatDAO.getAllThreats();
        alerts.sendBatchAlerts(threats);

        long critical = threats.stream()
                .filter(t -> t.getSeverity()
                        .equals("CRITICAL")).count();
        long high = threats.stream()
                .filter(t -> t.getSeverity()
                        .equals("HIGH")).count();

        alerts.sendDailySummary(
                threats.size(),
                (int) critical,
                (int) high,
                0
        );
    }

    // ── Banner ────────────────────────────────────

    private static void printBanner() {
        System.out.println("\n" + "═".repeat(55));
        System.out.println("   CYBER THREAT INTELLIGENCE FRAMEWORK");
        System.out.println("   Version 1.0 | Powered by Weka ML");
        System.out.println("   Started: " + DateHelper.now());
        System.out.println("═".repeat(55) + "\n");
    }

    private static void printDone() {
        System.out.println("\n" + "═".repeat(55));
        System.out.println("   ✅ ALL STEPS COMPLETE!");
        System.out.println("   Check reports/ for CSV files");
        System.out.println("   Check logs/ for system logs");
        System.out.println("   Check models/ for saved ML models");
        System.out.println("═".repeat(55) + "\n");
    }
}