package com.security.service;

import com.security.dao.RiskScoreDAO;
import com.security.model.RiskScore;
import com.security.service.ml.RealTimePredictor;
import com.security.utils.DateHelper;
import com.security.utils.Logger;
import com.security.utils.ValidationUtil;

/**
 * RiskScorer - Central risk scoring engine.
 * Integrates with RealTimePredictor (Weka ML).
 * Converts ML predictions into actionable risk scores.
 */
public class RiskScorer {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "RiskScorer";

    private final RealTimePredictor predictor  = new RealTimePredictor();
    private final RiskScoreDAO      riskDAO    = new RiskScoreDAO();
    private boolean modelReady = false;

    // ── Constructor ──────────────────────────────

    public RiskScorer() {
        // Try to load saved ML model
        modelReady = predictor.initialize();
        if (modelReady) {
            log.info(SOURCE, "ML model loaded successfully.");
        } else {
            log.warn(SOURCE,
                    "ML model not found. " +
                            "Run training first. Using rule-based fallback.");
        }
    }

    // ── Main Score Method ─────────────────────────

    /**
     * Calculates risk score for an IP address.
     * Uses ML model if available, falls back to rules if not.
     *
     * @param ipAddress  IP to evaluate
     * @param location   country of origin
     * @param loginTime  timestamp of login
     * @return RiskScore with level + score
     */
    public RiskScore scoreIp(String ipAddress,
                             String location,
                             String loginTime) {

        if (!ValidationUtil.isValidIp(ipAddress)) {
            log.warn(SOURCE, "Invalid IP: " + ipAddress);
            return buildScore(ipAddress, 0.0, "LOW", 0);
        }

        // Use ML model if ready
        if (modelReady) {
            log.info(SOURCE,
                    "Using Weka ML for: " + ipAddress);
            return predictor.predict(
                    ipAddress, location, loginTime);
        }

        // Fallback: rule-based scoring
        log.warn(SOURCE,
                "Using rule-based fallback for: " + ipAddress);
        return ruleBasedScore(ipAddress, location, loginTime);
    }

    // ── Rule-Based Fallback ──────────────────────

    /**
     * Simple rule-based scoring when ML model is not available.
     * Used on first run before training is complete.
     */
    private RiskScore ruleBasedScore(String ipAddress,
                                     String location,
                                     String loginTime) {
        double score = 0.0;

        // Rule 1: Foreign IP
        if (location != null && !location.equalsIgnoreCase("India")) {
            score += 25.0;
        }

        // Rule 2: Suspicious hour
        if (loginTime != null) {
            int hour = DateHelper.extractHour(loginTime);
            score += DateHelper.getTimeRiskScore(hour);
        }

        // Rule 3: Private IP = low risk
        if (ValidationUtil.isPrivateIp(ipAddress)) {
            score = Math.max(0, score - 20.0);
        }

        score = ValidationUtil.clampRiskScore(score);
        String level = toLevel(score);
        return buildScore(ipAddress, score, level, 0);
    }

    // ── Risk Level Helpers ───────────────────────

    /** Converts numeric score to risk level label. */
    public String toLevel(double score) {
        if (score >= 80) return "CRITICAL";
        if (score >= 60) return "HIGH";
        if (score >= 40) return "MEDIUM";
        return "LOW";
    }

    /** Returns emoji for a risk level. */
    public String toEmoji(String level) {
        return switch (level) {
            case "CRITICAL" -> "🔴";
            case "HIGH"     -> "🟠";
            case "MEDIUM"   -> "🟡";
            default         -> "🟢";
        };
    }

    /** Checks if model is loaded and ready. */
    public boolean isModelReady() {
        return modelReady;
    }

    // ── Private Builder ──────────────────────────

    private RiskScore buildScore(String ip, double score,
                                 String level, int fails) {
        return new RiskScore(
                0, ip, score, level,
                fails, 0.0, 0.0, 0.0,
                level, DateHelper.now()
        );
    }
}