package com.security.service.ml;

import com.security.config.DBConnection;
import com.security.utils.Logger;
import com.security.utils.ValidationUtil;
import weka.core.Instances;
import weka.core.converters.ArffLoader;

import java.io.File;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * DataPreprocessor - Prepares raw data for ML training.
 * Reads login logs from database, cleans them,
 * and converts to Weka-compatible format.
 */
public class DataPreprocessor {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "DataPreprocessor";

    // ── Load ARFF file ───────────────────────────

    /**
     * Loads the training data from .arff file.
     * Returns null if file not found or invalid.
     */
    public Instances loadArffFile(String filePath) {
        try {
            File file = new File(filePath);
            if (!file.exists()) {
                log.error(SOURCE, "ARFF file not found: " + filePath);
                return null;
            }

            ArffLoader loader = new ArffLoader();
            loader.setFile(file);
            Instances data = loader.getDataSet();

            // Last attribute is the class label
            data.setClassIndex(data.numAttributes() - 1);

            log.info(SOURCE, "Loaded " + data.numInstances()
                    + " training instances from: " + filePath);
            return data;

        } catch (Exception e) {
            log.error(SOURCE, "Failed to load ARFF: " + e.getMessage());
            return null;
        }
    }

    // ── Raw data from database ───────────────────

    /**
     * Extracts raw login records from database.
     * Each record: {ip, fail_count, hour, location, login_time}
     */
    public List<String[]> extractRawData() {
        List<String[]> records = new ArrayList<>();
        String sql = """
            SELECT ip_address,
                   COUNT(*) AS fail_count,
                   MIN(login_time) AS first_seen,
                   location
            FROM login_logs
            WHERE success = 0
            GROUP BY ip_address
            """;
        try (Connection conn = DBConnection.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            while (rs.next()) {
                String ip       = rs.getString("ip_address");
                String fails    = rs.getString("fail_count");
                String time     = rs.getString("first_seen");
                String location = rs.getString("location");

                // Skip invalid IPs
                if (!ValidationUtil.isValidIp(ip)) continue;

                records.add(new String[]{ip, fails, time, location});
            }
            log.info(SOURCE, "Extracted " + records.size()
                    + " raw records from database.");

        } catch (SQLException e) {
            log.error(SOURCE, "extractRawData failed: " + e.getMessage());
        }
        return records;
    }

    // ── Clean single value ───────────────────────

    /** Returns 0 if value is null or blank. */
    public String cleanNumeric(String value) {
        if (value == null || value.isBlank()) return "0";
        try {
            Double.parseDouble(value.trim());
            return value.trim();
        } catch (NumberFormatException e) {
            return "0";
        }
    }

    /** Returns "Unknown" if location is null or blank. */
    public String cleanLocation(String location) {
        if (location == null || location.isBlank()) return "Unknown";
        return location.trim();
    }

    // ── Summary ──────────────────────────────────

    /** Prints a summary of the loaded dataset. */
    public void printDataSummary(Instances data) {
        if (data == null) {
            log.warn(SOURCE, "No data to summarize.");
            return;
        }
        System.out.println("\n[DataPreprocessor] Dataset Summary");
        System.out.println("  Instances : " + data.numInstances());
        System.out.println("  Attributes: " + data.numAttributes());
        System.out.println("  Class     : "
                + data.classAttribute().name());
        System.out.println("  Labels    : "
                + data.classAttribute().numValues());
    }
}
