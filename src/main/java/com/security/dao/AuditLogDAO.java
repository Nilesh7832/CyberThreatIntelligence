package com.security.dao;

import com.security.config.DBConnection;
import com.security.model.AuditLog;
import com.security.utils.Logger;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * AuditLogDAO - Database operations for audit logs.
 * Every important system action is recorded here.
 * Provides full audit trail for compliance and forensics.
 */
public class AuditLogDAO {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "AuditLogDAO";

    // ── Insert ───────────────────────────────────

    /** Records a new audit event in the database. */
    public void insert(AuditLog entry) {
        String sql = """
            INSERT INTO audit_logs
            (timestamp, actor, action, target, details, severity)
            VALUES (?, ?, ?, ?, ?, ?)
            """;
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, entry.getTimestamp());
            ps.setString(2, entry.getActor());
            ps.setString(3, entry.getAction().name());
            ps.setString(4, entry.getTarget());
            ps.setString(5, entry.getDetails());
            ps.setString(6, entry.getSeverity());
            ps.executeUpdate();

            log.info(SOURCE, "Audit recorded: ["
                    + entry.getAction().name() + "] by "
                    + entry.getActor());

        } catch (SQLException e) {
            log.error(SOURCE, "Insert failed: " + e.getMessage());
        }
    }

    // ── Fetch All ────────────────────────────────

    /** Returns all audit logs ordered by timestamp descending. */
    public List<AuditLog> getAll() {
        List<AuditLog> list = new ArrayList<>();
        String sql = """
            SELECT * FROM audit_logs
            ORDER BY timestamp DESC
            """;
        try (Connection conn = DBConnection.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            while (rs.next()) list.add(mapRow(rs));

        } catch (SQLException e) {
            log.error(SOURCE, "getAll failed: " + e.getMessage());
        }
        return list;
    }

    // ── Fetch by Actor ───────────────────────────

    /** Returns all audit logs for a specific IP or username. */
    public List<AuditLog> getByActor(String actor) {
        List<AuditLog> list = new ArrayList<>();
        String sql = """
            SELECT * FROM audit_logs
            WHERE actor = ?
            ORDER BY timestamp DESC
            """;
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, actor);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) list.add(mapRow(rs));

        } catch (SQLException e) {
            log.error(SOURCE, "getByActor failed: " + e.getMessage());
        }
        return list;
    }

    // ── Fetch by Action ──────────────────────────

    /** Returns all audit logs for a specific action type. */
    public List<AuditLog> getByAction(AuditLog.Action action) {
        List<AuditLog> list = new ArrayList<>();
        String sql = """
            SELECT * FROM audit_logs
            WHERE action = ?
            ORDER BY timestamp DESC
            """;
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, action.name());
            ResultSet rs = ps.executeQuery();
            while (rs.next()) list.add(mapRow(rs));

        } catch (SQLException e) {
            log.error(SOURCE, "getByAction failed: " + e.getMessage());
        }
        return list;
    }

    // ── Row Mapper ───────────────────────────────

    /** Maps a ResultSet row to an AuditLog object. */
    private AuditLog mapRow(ResultSet rs) throws SQLException {
        return new AuditLog(
                rs.getInt("id"),
                rs.getString("timestamp"),
                rs.getString("actor"),
                AuditLog.Action.valueOf(rs.getString("action")),
                rs.getString("target"),
                rs.getString("details"),
                rs.getString("severity")
        );
    }
}