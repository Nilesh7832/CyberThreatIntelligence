package com.security.utils;

import com.security.config.AppConfig;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Logger - Centralized logging system.
 * Writes logs to both console and log file.
 * Supports INFO, WARN, ERROR, and SECURITY levels.
 */
public class Logger {

    // Log levels
    public enum Level { INFO, WARN, ERROR, SECURITY }

    private static Logger instance;
    private final String logFilePath;
    private final DateTimeFormatter formatter =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // ── Constructor ──────────────────────────────
    private Logger() {
        this.logFilePath = AppConfig.getInstance().getLogFilePath();
        initLogFile();
    }

    // ── Singleton accessor ───────────────────────
    public static synchronized Logger getInstance() {
        if (instance == null) {
            instance = new Logger();
        }
        return instance;
    }

    // ── Create log directory if not exists ───────
    private void initLogFile() {
        try {
            Files.createDirectories(
                    Paths.get(logFilePath).getParent());
        } catch (IOException e) {
            System.err.println("[Logger] Could not create log directory: "
                    + e.getMessage());
        }
    }

    // ── Core log method ──────────────────────────
    private void log(Level level, String source, String message) {
        String timestamp = LocalDateTime.now().format(formatter);
        String entry = String.format("[%s] [%-8s] [%s] %s",
                timestamp, level.name(), source, message);

        // Print to console
        if (level == Level.ERROR || level == Level.SECURITY) {
            System.err.println(entry);
        } else {
            System.out.println(entry);
        }

        // Write to log file
        writeToFile(entry);
    }

    // ── Write to file ────────────────────────────
    private void writeToFile(String entry) {
        try (PrintWriter pw = new PrintWriter(
                new FileWriter(logFilePath, true))) {
            pw.println(entry);
        } catch (IOException e) {
            System.err.println("[Logger] File write failed: "
                    + e.getMessage());
        }
    }

    // ── Public API ───────────────────────────────

    public void info(String source, String message) {
        log(Level.INFO, source, message);
    }

    public void warn(String source, String message) {
        log(Level.WARN, source, message);
    }

    public void error(String source, String message) {
        log(Level.ERROR, source, message);
    }

    /** Use this for all security-related events. */
    public void security(String source, String message) {
        log(Level.SECURITY, source, message);
    }
}