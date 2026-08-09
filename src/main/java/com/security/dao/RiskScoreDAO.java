package com.security.dao;

import com.security.config.DBConnection;
import com.security.model.RiskScore;
import com.security.utils.Logger;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * RiskScoreDAO - Database operations for risk scores.
 * Handles insert, fetch, and history queries.
 */
public class RiskScoreDAO {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "RiskScoreDAO";

    // ── Insert ───────────────────────────────────

    /** Saves a new risk score record to the database. */
    public void insert(RiskScore rs) {
        String sql = """
            INSERT INTO risk_scores
            (ip_address, total_score, risk_level, fail_count,
             geo_risk, time_risk, speed_risk, ml_prediction, calculated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, rs.getIpAddress());
            ps.setDouble(2, rs.getTotalScore());
            ps.setString(3, rs.getRiskLevel());
            ps.setInt(4,    rs.getFailCount());
            ps.setDouble(5, rs.getGeoRisk());
            ps.setDouble(6, rs.getTimeRisk());
            ps.setDouble(7, rs.getSpeedRisk());
            ps.setString(8, rs.getMlPrediction());
            ps.setString(9, rs.getCalculatedAt());
            ps.executeUpdate();

            log.info(SOURCE, "Risk score saved for IP: "
                    + rs.getIpAddress()
                    + " | Score: " + rs.getTotalScore()
                    + " | Level: " + rs.getRiskLevel());

        } catch (SQLException e) {
            log.error(SOURCE, "Insert failed: " + e.getMessage());
        }
    }

    // ── Fetch All ────────────────────────────────

    /** Returns all risk scores ordered by score descending. */
    public List<RiskScore> getAll() {
        List<RiskScore> list = new ArrayList<>();
        String sql = """
            SELECT * FROM risk_scores
            ORDER BY total_score DESC
            """;
        try (Connection conn = DBConnection.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            while (rs.next()) {
                list.add(mapRow(rs));
            }
        } catch (SQLException e) {
            log.error(SOURCE, "getAll failed: " + e.getMessage());
        }
        return list;
    }

    // ── Fetch by IP ──────────────────────────────

    /** Returns the latest risk score for a given IP. */
    public RiskScore getLatestByIp(String ipAddress) {
        String sql = """
            SELECT * FROM risk_scores
            WHERE ip_address = ?
            ORDER BY calculated_at DESC
            LIMIT 1
            """;
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, ipAddress);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return mapRow(rs);

        } catch (SQLException e) {
            log.error(SOURCE, "getLatestByIp failed: " + e.getMessage());
        }
        return null;
    }

    // ── Fetch Critical ───────────────────────────

    /** Returns all IPs with CRITICAL risk level. */
    public List<RiskScore> getCritical() {
        List<RiskScore> list = new ArrayList<>();
        String sql = """
            SELECT * FROM risk_scores
            WHERE risk_level = 'CRITICAL'
            ORDER BY total_score DESC
            """;
        try (Connection conn = DBConnection.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            while (rs.next()) list.add(mapRow(rs));

        } catch (SQLException e) {
            log.error(SOURCE, "getCritical failed: " + e.getMessage());
        }
        return list;
    }

    // ── Row Mapper ───────────────────────────────

    /** Maps a ResultSet row to a RiskScore object. */
    private RiskScore mapRow(ResultSet rs) throws SQLException {
        return new RiskScore(
                rs.getInt("id"),
                rs.getString("ip_address"),
                rs.getDouble("total_score"),
                rs.getString("risk_level"),
                rs.getInt("fail_count"),
                rs.getDouble("geo_risk"),
                rs.getDouble("time_risk"),
                rs.getDouble("speed_risk"),
                rs.getString("ml_prediction"),
                rs.getString("calculated_at")
        );
    }
}
