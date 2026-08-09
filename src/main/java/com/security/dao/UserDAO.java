package com.security.dao;

import com.security.config.DBConnection;
import com.security.model.User;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class UserDAO {

    // Naya user database mein save karo
    public void insertUser(User user) {
        String sql = "INSERT INTO users (username, email, role, created_at) VALUES (?, ?, ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, user.getUsername());
            ps.setString(2, user.getEmail());
            ps.setString(3, user.getRole());
            ps.setString(4, user.getCreatedAt());
            ps.executeUpdate();
            System.out.println("✅ User inserted: " + user.getUsername());

        } catch (SQLException e) {
            System.out.println("❌ Insert failed: " + e.getMessage());
        }
    }

    // Saare users lao
    public List<User> getAllUsers() {
        List<User> users = new ArrayList<>();
        String sql = "SELECT * FROM users";
        try (Connection conn = DBConnection.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            while (rs.next()) {
                users.add(new User(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("email"),
                        rs.getString("role"),
                        rs.getString("created_at")
                ));
            }
        } catch (SQLException e) {
            System.out.println("❌ Fetch failed: " + e.getMessage());
        }
        return users;
    }

    // Username se user dhundo
    public User getUserByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return new User(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("email"),
                        rs.getString("role"),
                        rs.getString("created_at")
                );
            }
        } catch (SQLException e) {
            System.out.println("❌ Search failed: " + e.getMessage());
        }
        return null;
    }
}