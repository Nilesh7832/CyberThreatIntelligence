package com.security.dao;

import com.security.config.DBConnection;
import com.security.model.LoginLog;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class LoginDAO {

    // Naya login record save karo
    public void insertLoginLog(LoginLog log) {
        String sql = "INSERT INTO login_logs (username, ip_address, login_time, success, failure_reason, location) VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, log.getUsername());
            ps.setString(2, log.getIpAddress());
            ps.setString(3, log.getLoginTime());
            ps.setBoolean(4, log.isSuccess());
            ps.setString(5, log.getFailureReason());
            ps.setString(6, log.getLocation());
            ps.executeUpdate();
            System.out.println("✅ Login log saved for: " + log.getUsername());

        } catch (SQLException e) {
            System.out.println("❌ Login log insert failed: " + e.getMessage());
        }
    }

    // Saare failed logins lao
    public List<LoginLog> getFailedLogins() {
        List<LoginLog> logs = new ArrayList<>();
        String sql = "SELECT * FROM login_logs WHERE success = 0";
        try (Connection conn = DBConnection.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            while (rs.next()) {
                logs.add(new LoginLog(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("ip_address"),
                        rs.getString("login_time"),
                        rs.getBoolean("success"),
                        rs.getString("failure_reason"),
                        rs.getString("location")
                ));
            }
        } catch (SQLException e) {
            System.out.println("❌ Failed login fetch error: " + e.getMessage());
        }
        return logs;
    }

    // Ek IP ke saare logins lao
    public List<LoginLog> getLoginsByIp(String ipAddress) {
        List<LoginLog> logs = new ArrayList<>();
        String sql = "SELECT * FROM login_logs WHERE ip_address = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, ipAddress);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                logs.add(new LoginLog(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("ip_address"),
                        rs.getString("login_time"),
                        rs.getBoolean("success"),
                        rs.getString("failure_reason"),
                        rs.getString("location")
                ));
            }
        } catch (SQLException e) {
            System.out.println("❌ IP search failed: " + e.getMessage());
        }
        return logs;
    }

    // Count karo - ek IP ne kitni baar fail kiya
    public int countFailedLoginsByIp(String ipAddress) {
        String sql = "SELECT COUNT(*) FROM login_logs WHERE ip_address = ? AND success = 0";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, ipAddress);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getInt(1);

        } catch (SQLException e) {
            System.out.println("❌ Count failed: " + e.getMessage());
        }
        return 0;
    }
}