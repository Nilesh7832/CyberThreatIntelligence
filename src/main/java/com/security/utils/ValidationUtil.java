package com.security.utils;

import java.util.regex.Pattern;

/**
 * ValidationUtil - Input validation helper.
 * Validates IPs, usernames, emails, and timestamps.
 * Used across all layers to ensure clean data.
 */
public class ValidationUtil {

    // ── Regex Patterns ───────────────────────────
    private static final Pattern IP_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}" +
                    "(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$");

    private static final Pattern USERNAME_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_]{3,50}$");

    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile(
            "^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}$");

    // ── Private constructor (utility class) ──────
    private ValidationUtil() {}

    // ── IP Validation ────────────────────────────

    /**
     * Checks if a string is a valid IPv4 address.
     * Example: "192.168.1.1" → true
     */
    public static boolean isValidIp(String ip) {
        if (ip == null || ip.isBlank()) return false;
        return IP_PATTERN.matcher(ip.trim()).matches();
    }

    /**
     * Checks if IP is in private/internal range.
     * 192.168.x.x, 10.x.x.x, 172.16-31.x.x
     */
    public static boolean isPrivateIp(String ip) {
        if (!isValidIp(ip)) return false;
        return ip.startsWith("192.168.") ||
                ip.startsWith("10.")      ||
                ip.startsWith("172.16.") ||
                ip.startsWith("172.17.") ||
                ip.startsWith("127.");
    }

    // ── String Validation ────────────────────────

    /** Checks if a string is null or blank. */
    public static boolean isNullOrEmpty(String value) {
        return value == null || value.isBlank();
    }

    /** Validates username format (3-50 alphanumeric chars). */
    public static boolean isValidUsername(String username) {
        if (isNullOrEmpty(username)) return false;
        return USERNAME_PATTERN.matcher(username.trim()).matches();
    }

    /** Validates email format. */
    public static boolean isValidEmail(String email) {
        if (isNullOrEmpty(email)) return false;
        return EMAIL_PATTERN.matcher(email.trim()).matches();
    }

    /** Validates timestamp format: yyyy-MM-dd HH:mm:ss */
    public static boolean isValidTimestamp(String timestamp) {
        if (isNullOrEmpty(timestamp)) return false;
        return TIMESTAMP_PATTERN.matcher(timestamp.trim()).matches();
    }

    // ── Risk Score Validation ────────────────────

    /** Checks if a risk score is in valid range (0-100). */
    public static boolean isValidRiskScore(double score) {
        return score >= 0.0 && score <= 100.0;
    }

    /** Clamps a risk score to 0-100 range. */
    public static double clampRiskScore(double score) {
        return Math.max(0.0, Math.min(100.0, score));
    }

    // ── Severity Validation ──────────────────────

    /** Checks if severity is one of the allowed values. */
    public static boolean isValidSeverity(String severity) {
        if (isNullOrEmpty(severity)) return false;
        return switch (severity.toUpperCase()) {
            case "LOW", "MEDIUM", "HIGH", "CRITICAL" -> true;
            default -> false;
        };
    }
}