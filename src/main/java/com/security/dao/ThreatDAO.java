package com.security.dao;

import com.security.config.DBConnection;
import com.security.model.ThreatAlert;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class ThreatDAO {

    // Naya threat save karo
    public void insertThreat(ThreatAlert threat) {
        String sql = "INSERT INTO threat_alerts (threat_type, source_ip, target_system, severity, detected_at, status, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, threat.getThreatType());
            ps.setString(2, threat.getSourceIp());
            ps.setString(3, threat.getTargetSystem());
            ps.setString(4, threat.getSeverity());
            ps.setString(5, threat.getDetectedAt());
            ps.setString(6, threat.getStatus());
            ps.setDouble(7, threat.getRiskScore());
            ps.executeUpdate();
            System.out.println("✅ Threat saved: " + threat.getThreatType());

        } catch (SQLException e) {
            System.out.println("❌ Threat insert failed: " + e.getMessage());
        }
    }

    // Saare threats lao
    public List<ThreatAlert> getAllThreats() {
        List<ThreatAlert> threats = new ArrayList<>();
        String sql = "SELECT * FROM threat_alerts ORDER BY detected_at DESC";
        try (Connection conn = DBConnection.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            while (rs.next()) {
                threats.add(new ThreatAlert(
                        rs.getInt("id"),
                        rs.getString("threat_type"),
                        rs.getString("source_ip"),
                        rs.getString("target_system"),
                        rs.getString("severity"),
                        rs.getString("detected_at"),
                        rs.getString("status"),
                        rs.getDouble("risk_score")
                ));
            }
        } catch (SQLException e) {
            System.out.println("❌ Fetch threats failed: " + e.getMessage());
        }
        return threats;
    }

    // Sirf CRITICAL threats lao
    public List<ThreatAlert> getCriticalThreats() {
        List<ThreatAlert> threats = new ArrayList<>();
        String sql = "SELECT * FROM threat_alerts WHERE severity = 'CRITICAL'";
        try (Connection conn = DBConnection.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            while (rs.next()) {
                threats.add(new ThreatAlert(
                        rs.getInt("id"),
                        rs.getString("threat_type"),
                        rs.getString("source_ip"),
                        rs.getString("target_system"),
                        rs.getString("severity"),
                        rs.getString("detected_at"),
                        rs.getString("status"),
                        rs.getDouble("risk_score")
                ));
            }
        } catch (SQLException e) {
            System.out.println("❌ Critical threats fetch failed: " + e.getMessage());
        }
        return threats;
    }

    // Threat ka status update karo
    public void updateThreatStatus(int id, String status) {
        String sql = "UPDATE threat_alerts SET status = ? WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, status);
            ps.setInt(2, id);
            ps.executeUpdate();
            System.out.println("✅ Threat #" + id + " status updated to: " + status);

        } catch (SQLException e) {
            System.out.println("❌ Status update failed: " + e.getMessage());
        }
    }
}