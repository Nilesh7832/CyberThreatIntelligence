package com.security.utils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/**
 * DateHelper - Centralized date and time utility.
 * All date operations go through this class.
 * No raw date handling elsewhere in the codebase.
 */
public class DateHelper {

    // Standard timestamp format used across the system
    public static final String TIMESTAMP_FORMAT = "yyyy-MM-dd HH:mm:ss";
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern(TIMESTAMP_FORMAT);

    // ── Private constructor (utility class) ──────
    private DateHelper() {}

    // ── Current Time ─────────────────────────────

    /** Returns current timestamp as formatted string. */
    public static String now() {
        return LocalDateTime.now().format(FORMATTER);
    }

    /** Returns current hour (0-23). */
    public static int currentHour() {
        return LocalDateTime.now().getHour();
    }

    // ── Parsing ──────────────────────────────────

    /** Parses a timestamp string to LocalDateTime. */
    public static LocalDateTime parse(String timestamp) {
        try {
            return LocalDateTime.parse(timestamp.trim(), FORMATTER);
        } catch (Exception e) {
            Logger.getInstance().error("DateHelper",
                    "Failed to parse timestamp: " + timestamp);
            return null;
        }
    }

    /** Extracts hour (0-23) from a timestamp string. */
    public static int extractHour(String timestamp) {
        LocalDateTime dt = parse(timestamp);
        return (dt != null) ? dt.getHour() : -1;
    }

    // ── Time Window Checks ───────────────────────

    /**
     * Checks if a timestamp is within the last N minutes.
     * Used for brute-force time-window detection.
     */
    public static boolean isWithinLastMinutes(String timestamp, int minutes) {
        LocalDateTime dt = parse(timestamp);
        if (dt == null) return false;
        LocalDateTime cutoff = LocalDateTime.now()
                .minus(minutes, ChronoUnit.MINUTES);
        return dt.isAfter(cutoff);
    }

    /**
     * Returns minutes elapsed since a given timestamp.
     */
    public static long minutesSince(String timestamp) {
        LocalDateTime dt = parse(timestamp);
        if (dt == null) return -1;
        return ChronoUnit.MINUTES.between(dt, LocalDateTime.now());
    }

    // ── Risk Helpers ─────────────────────────────

    /**
     * Checks if an hour is suspicious (off-hours = midnight to 5am).
     * Off-hours logins carry higher risk.
     */
    public static boolean isSuspiciousHour(int hour) {
        return hour >= 0 && hour <= 5;
    }

    /**
     * Checks if an hour is night-time (10pm to 7am).
     */
    public static boolean isNightTime(int hour) {
        return hour >= 22 || hour <= 7;
    }

    /**
     * Returns a time-risk score based on login hour.
     * Midnight attacks score highest.
     */
    public static double getTimeRiskScore(int hour) {
        if (isSuspiciousHour(hour)) return 20.0;   // 12am–5am: high risk
        if (isNightTime(hour))      return 10.0;   // 10pm–7am: medium risk
        return 0.0;                                 // Daytime: no risk
    }

    /** Returns formatted string of current date for report filenames. */
    public static String todayForFilename() {
        return LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd"));
    }
}