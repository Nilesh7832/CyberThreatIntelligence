package com.security.config;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * DBConnection - Manages the single SQLite database connection.
 * Singleton pattern - only one connection exists at a time.
 */
public class DBConnection {

    private static Connection connection = null;

    // ── Private constructor ──────────────────────
    private DBConnection() {}

    // ── Get Connection ───────────────────────────

    /**
     * Returns the active database connection.
     * Creates a new one if not already open.
     */
    public static Connection getConnection() {
        try {
            if (connection == null || connection.isClosed()) {
                String url = AppConfig.getInstance().getDbUrl();
                connection = DriverManager.getConnection(url);
                // Enable foreign keys
                connection.createStatement()
                        .execute("PRAGMA foreign_keys = ON");
            }
        } catch (SQLException e) {
            System.err.println(
                    "[DBConnection] Failed to connect: "
                            + e.getMessage());
        }
        return connection;
    }

    // ── Close Connection ─────────────────────────

    /**
     * Closes the database connection.
     * Call this when the application shuts down.
     */
    public static void closeConnection() {
        if (connection != null) {
            try {
                connection.close();
                connection = null;
                System.out.println(
                        "[DBConnection] Connection closed.");
            } catch (SQLException e) {
                System.err.println(
                        "[DBConnection] Close failed: "
                                + e.getMessage());
            }
        }
    }
}