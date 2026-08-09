package com.security.service.ml;

import com.security.dao.LoginDAO;
import com.security.utils.DateHelper;
import com.security.utils.Logger;
import com.security.utils.ValidationUtil;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instances;

import java.util.ArrayList;

/**
 * FeatureExtractor - Converts raw login data into ML features.
 * Extracts 6 numeric features from each IP's login history.
 * These features feed directly into the Weka ML model.
 *
 * Features:
 *   1. fail_count   - Total failed login attempts
 *   2. hour         - Hour of first suspicious login (0-23)
 *   3. is_foreign   - 1 if non-Indian IP, 0 otherwise
 *   4. attack_speed - How fast attempts came (0-3 scale)
 *   5. geo_risk     - Geographic risk score (0-25)
 *   6. time_risk    - Time-of-day risk score (0-20)
 */
public class FeatureExtractor {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "FeatureExtractor";
    private final LoginDAO loginDAO = new LoginDAO();

    // ── Build Weka Attribute List ─────────────────

    /**
     * Defines all features + class label for Weka dataset.
     * Must match training_data.arff attribute order exactly.
     */
    public ArrayList<Attribute> buildAttributes() {
        ArrayList<Attribute> attrs = new ArrayList<>();

        // Numeric features
        attrs.add(new Attribute("fail_count"));
        attrs.add(new Attribute("hour"));
        attrs.add(new Attribute("is_foreign"));
        attrs.add(new Attribute("attack_speed"));
        attrs.add(new Attribute("geo_risk"));
        attrs.add(new Attribute("time_risk"));

        // Class label (output)
        ArrayList<String> labels = new ArrayList<>();
        labels.add("LOW");
        labels.add("MEDIUM");
        labels.add("HIGH");
        labels.add("CRITICAL");
        attrs.add(new Attribute("risk_level", labels));

        return attrs;
    }

    /**
     * Creates an empty Weka Instances dataset with the
     * correct attribute structure.
     */
    public Instances createEmptyDataset() {
        ArrayList<Attribute> attrs = buildAttributes();
        Instances dataset = new Instances("RiskData", attrs, 0);
        // Last attribute is the class
        dataset.setClassIndex(attrs.size() - 1);
        return dataset;
    }

    // ── Extract Features for One IP ──────────────

    /**
     * Extracts all 6 features for a given IP address.
     * Returns a double array: {fail_count, hour, is_foreign,
     *                          attack_speed, geo_risk, time_risk}
     */
    public double[] extractFeatures(String ipAddress,
                                    String location,
                                    String loginTime) {
        // Validate input
        if (!ValidationUtil.isValidIp(ipAddress)) {
            log.warn(SOURCE, "Invalid IP skipped: " + ipAddress);
            return new double[]{0, 12, 0, 0, 0, 0};
        }

        // 1. Fail count from database
        int failCount = loginDAO.countFailedLoginsByIp(ipAddress);

        // 2. Login hour
        int hour = (loginTime != null)
                ? DateHelper.extractHour(loginTime) : 12;
        if (hour < 0) hour = 12;

        // 3. Foreign IP check
        double isForeign = isHighRiskCountry(location) ? 1.0 : 0.0;

        // 4. Attack speed (0=slow, 1=medium, 2=fast, 3=very fast)
        double speed = calculateSpeed(failCount);

        // 5. Geographic risk score
        double geoRisk = calculateGeoRisk(location);

        // 6. Time-of-day risk score
        double timeRisk = DateHelper.getTimeRiskScore(hour);

        log.info(SOURCE, String.format(
                "Features for %s → fails=%d, hour=%d, " +
                        "foreign=%.0f, speed=%.0f, geo=%.0f, time=%.0f",
                ipAddress, failCount, hour,
                isForeign, speed, geoRisk, timeRisk));

        return new double[]{
                failCount, hour, isForeign,
                speed, geoRisk, timeRisk
        };
    }

    /**
     * Builds a single Weka DenseInstance from features.
     * Used during real-time prediction.
     */
    public DenseInstance buildInstance(Instances dataset,
                                       double[] features) {
        // +1 for the class label slot (set to 0 as placeholder)
        double[] values = new double[features.length + 1];
        System.arraycopy(features, 0, values, 0, features.length);
        values[features.length] = 0; // placeholder for class

        DenseInstance instance = new DenseInstance(1.0, values);
        instance.setDataset(dataset);
        return instance;
    }

    // ── Private Helpers ──────────────────────────

    /** Checks if location is a known high-risk country. */
    private boolean isHighRiskCountry(String location) {
        if (location == null || location.isBlank()) return false;
        String loc = location.toUpperCase();
        return loc.equals("CHINA")   || loc.equals("CN") ||
                loc.equals("RUSSIA")  || loc.equals("RU") ||
                loc.equals("NIGERIA") || loc.equals("NG") ||
                loc.equals("KOREA")   || loc.equals("KP") ||
                loc.equals("IRAN")    || loc.equals("IR") ||
                loc.equals("UNKNOWN");
    }

    /** Calculates attack speed score (0-3) from fail count. */
    private double calculateSpeed(int failCount) {
        if (failCount >= 10) return 3.0;
        if (failCount >= 6)  return 2.0;
        if (failCount >= 3)  return 1.0;
        return 0.0;
    }

    /** Returns geographic risk score (0-25). */
    private double calculateGeoRisk(String location) {
        if (location == null || location.isBlank()) return 10.0;
        String loc = location.toUpperCase();
        if (loc.equals("INDIA") || loc.equals("IN")) return 0.0;
        if (isHighRiskCountry(location))              return 25.0;
        return 15.0; // Other foreign country
    }
}