package com.security.service.ml;

import com.security.config.AppConfig;
import com.security.dao.RiskScoreDAO;
import com.security.model.RiskScore;
import com.security.utils.DateHelper;
import com.security.utils.Logger;
import com.security.utils.ValidationUtil;
import weka.classifiers.Classifier;
import weka.core.DenseInstance;
import weka.core.Instances;

/**
 * RealTimePredictor - Live ML-based threat prediction.
 * Flow:
 *   1. Load saved model from disk
 *   2. Extract features for incoming IP
 *   3. Run Weka prediction
 *   4. Save result to risk_scores table
 *   5. Return risk level + score
 */
public class RealTimePredictor {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "RealTimePredictor";

    private final AppConfig        config      = AppConfig.getInstance();
    private final ModelPersistence persistence = new ModelPersistence();
    private final FeatureExtractor extractor   = new FeatureExtractor();
    private final RiskScoreDAO     riskDAO     = new RiskScoreDAO();

    // Loaded model and dataset structure
    private Classifier classifier;
    private Instances  datasetStructure;

    // ── Initialise ───────────────────────────────

    /**
     * Loads the saved model from disk.
     * Must be called before any prediction.
     * Returns false if no model file found.
     */
    public boolean initialize() {
        // Load saved model
        classifier = persistence.loadPrimaryModel();
        if (classifier == null) {
            log.warn(SOURCE,
                    "No saved model found. Train first.");
            return false;
        }

        // Build empty dataset for structure reference
        datasetStructure = extractor.createEmptyDataset();

        log.info(SOURCE, "RealTimePredictor ready.");
        return true;
    }

    // ── Main Predict Method ──────────────────────

    /**
     * Predicts risk level for an IP address in real time.
     *
     * @param ipAddress  IP to evaluate
     * @param location   country/location of the IP
     * @param loginTime  timestamp of the login attempt
     * @return RiskScore object with prediction + score
     */
    public RiskScore predict(String ipAddress,
                             String location,
                             String loginTime) {

        // Validate IP
        if (!ValidationUtil.isValidIp(ipAddress)) {
            log.warn(SOURCE, "Invalid IP: " + ipAddress);
            return buildDefaultScore(ipAddress);
        }

        // Model not loaded
        if (classifier == null || datasetStructure == null) {
            log.warn(SOURCE,
                    "Model not initialized. Call initialize() first.");
            return buildDefaultScore(ipAddress);
        }

        try {
            // Step 1: Extract features
            double[] features = extractor.extractFeatures(
                    ipAddress, location, loginTime);

            // Step 2: Build Weka instance
            DenseInstance instance = extractor.buildInstance(
                    datasetStructure, features);

            // Step 3: Run ML prediction
            double classIndex = classifier.classifyInstance(instance);
            String prediction = datasetStructure
                    .classAttribute()
                    .value((int) classIndex);

            // Step 4: Build RiskScore object
            RiskScore result = new RiskScore(
                    0,
                    ipAddress,
                    toScore(prediction),
                    prediction,
                    (int) features[0],   // fail_count
                    features[4],          // geo_risk
                    features[5],          // time_risk
                    features[3],          // speed_risk
                    prediction,
                    DateHelper.now()
            );

            // Step 5: Save to database
            riskDAO.insert(result);

            // Step 6: Log result
            log.security(SOURCE, String.format(
                    "PREDICTION → IP=%-16s | Level=%-8s | Score=%.1f",
                    ipAddress, prediction, result.getTotalScore()));

            printPrediction(ipAddress, features,
                    prediction, result.getTotalScore());

            return result;

        } catch (Exception e) {
            log.error(SOURCE,
                    "Prediction failed for " + ipAddress
                            + ": " + e.getMessage());
            return buildDefaultScore(ipAddress);
        }
    }

    // ── Batch Predict ────────────────────────────

    /**
     * Predicts risk for multiple IPs at once.
     * Useful for scanning all IPs in login_logs.
     */
    public void predictBatch(java.util.List<String[]> records) {
        log.info(SOURCE, "Batch prediction for "
                + records.size() + " records...");

        int count = 0;
        for (String[] record : records) {
            // record = {ip, fail_count, loginTime, location}
            if (record.length >= 4) {
                predict(record[0], record[3], record[2]);
                count++;
            }
        }
        log.info(SOURCE,
                "Batch prediction complete. Processed: " + count);
    }

    // ── Private Helpers ──────────────────────────

    /**
     * Converts risk level label to numeric score.
     * Used to populate the total_score column.
     */
    private double toScore(String level) {
        return switch (level) {
            case "CRITICAL" -> 90.0;
            case "HIGH"     -> 70.0;
            case "MEDIUM"   -> 45.0;
            default         -> 15.0;
        };
    }

    /**
     * Returns a default LOW-risk score when
     * prediction cannot be run (invalid input etc).
     */
    private RiskScore buildDefaultScore(String ipAddress) {
        return new RiskScore(
                0, ipAddress, 0.0, "LOW",
                0, 0.0, 0.0, 0.0,
                "DEFAULT", DateHelper.now()
        );
    }

    /** Prints a formatted prediction result to console. */
    private void printPrediction(String ip, double[] features,
                                 String level, double score) {
        String emoji = switch (level) {
            case "CRITICAL" -> "🔴";
            case "HIGH"     -> "🟠";
            case "MEDIUM"   -> "🟡";
            default         -> "🟢";
        };
        System.out.println("\n[ML Prediction]");
        System.out.println("  IP           : " + ip);
        System.out.println("  Fail Count   : " + (int) features[0]);
        System.out.println("  Login Hour   : " + (int) features[1]);
        System.out.println("  Is Foreign   : "
                + (features[2] == 1.0 ? "Yes" : "No"));
        System.out.println("  Geo Risk     : " + features[4]);
        System.out.println("  Time Risk    : " + features[5]);
        System.out.println("  Prediction   : "
                + emoji + " " + level);
        System.out.println("  Risk Score   : " + score + "/100");
    }
}
