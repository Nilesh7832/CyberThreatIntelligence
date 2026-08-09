package com.security.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * AppConfig - Central configuration manager.
 * Loads all settings from config.properties.
 * Singleton pattern - only one instance exists.
 */
public class AppConfig {

    // Single instance
    private static AppConfig instance;
    private final Properties props;

    // ── Constructor ──────────────────────────────
    private AppConfig() {
        props = new Properties();
        loadConfig();
    }

    // ── Singleton accessor ───────────────────────
    public static synchronized AppConfig getInstance() {
        if (instance == null) {
            instance = new AppConfig();
        }
        return instance;
    }

    // ── Load config from classpath ───────────────
    private void loadConfig() {
        try (InputStream in =
                     getClass().getResourceAsStream("/config.properties")) {
            if (in == null) {
                throw new RuntimeException(
                        "config.properties not found on classpath");
            }
            props.load(in);
            System.out.println("[AppConfig] Configuration loaded.");
        } catch (IOException e) {
            throw new RuntimeException(
                    "[AppConfig] Failed to load config: " + e.getMessage());
        }
    }

    // ── Getters ──────────────────────────────────

    /** Returns a String property value. */
    public String get(String key) {
        return props.getProperty(key, "");
    }

    /** Returns an int property value with a fallback default. */
    public int getInt(String key, int defaultValue) {
        try {
            return Integer.parseInt(props.getProperty(key,
                    String.valueOf(defaultValue)).trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /** Returns a boolean property value. */
    public boolean getBoolean(String key, boolean defaultValue) {
        String val = props.getProperty(key);
        if (val == null) return defaultValue;
        return Boolean.parseBoolean(val.trim());
    }

    // ── Convenience accessors ─────────────────────

    public String getDbUrl() {
        return get("db.url");
    }

    public int getBruteForceThreshold() {
        return getInt("threat.brute_force.threshold", 5);
    }

    public int getBruteForceWindowMinutes() {
        return getInt("threat.brute_force.window_minutes", 10);
    }

    public int getCriticalRiskThreshold() {
        return getInt("risk.critical.threshold", 80);
    }

    public int getHighRiskThreshold() {
        return getInt("risk.high.threshold", 60);
    }

    public int getMediumRiskThreshold() {
        return getInt("risk.medium.threshold", 40);
    }

    public String getModelPath() {
        return get("ml.model.path");
    }

    public String getTrainingDataPath() {
        return get("ml.training.data.path");
    }

    public int getCrossValidationFolds() {
        return getInt("ml.cross_validation.folds", 10);
    }

    public String getReportOutputPath() {
        return get("report.output.path");
    }

    public String getDashboardPath() {
        return get("dashboard.output.path");
    }

    public String getLogFilePath() {
        return get("log.file.path");
    }

    public boolean isEmailAlertEnabled() {
        return getBoolean("alert.email.enabled", false);
    }

    public String getBlacklistPath() {
        return get("blacklist.file.path");
    }
}