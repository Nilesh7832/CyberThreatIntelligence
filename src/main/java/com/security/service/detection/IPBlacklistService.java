package com.security.service.detection;

import com.security.config.DBConnection;
import com.security.dao.AuditLogDAO;
import com.security.model.AuditLog;
import com.security.utils.DateHelper;
import com.security.utils.Logger;
import com.security.utils.ValidationUtil;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * IPBlacklistService - Manages the IP blacklist.
 * Blocks dangerous IPs automatically.
 * Provides check, block, unblock, and list operations.
 */
public class IPBlacklistService {

    private static final Logger   log      = Logger.getInstance();
    private static final String   SOURCE   = "IPBlacklistService";
    private final AuditLogDAO     auditDAO = new AuditLogDAO();

    // ── Check if IP is Blocked ────────────────────

    /**
     * Returns true if the IP is currently blacklisted.
     * Used as a gate before processing any login.
     */
    public boolean isBlocked(String ipAddress) {
        if (!ValidationUtil.isValidIp(ipAddress)) return false;

        String sql = """
            SELECT COUNT(*) FROM ip_blacklist
            WHERE ip_address = ? AND is_active = 1
            """;
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, ipAddress);
            ResultSet rs = ps.executeQuery();
            if (rs.next() && rs.getInt(1) > 0) {
                log.security(SOURCE,
                        "Blocked IP attempted access: " + ipAddress);
                return true;
            }
        } catch (SQLException e) {
            log.error(SOURCE, "isBlocked failed: " + e.getMessage());
        }
        return false;
    }

    // ── Block an IP ───────────────────────────────

    /**
     * Adds an IP to the blacklist.
     * Called automatically when CRITICAL threat is detected.
     *
     * @param ipAddress  IP to block
     * @param reason     why it was blocked
     * @param blockedBy  who triggered the block (SYSTEM/ADMIN)
     */
    public boolean blockIp(String ipAddress,
                           String reason,
                           String blockedBy) {

        if (!ValidationUtil.isValidIp(ipAddress)) {
            log.warn(SOURCE, "Cannot block invalid IP: " + ipAddress);
            return false;
        }

        // Don't block private/internal IPs
        if (ValidationUtil.isPrivateIp(ipAddress)) {
            log.warn(SOURCE,
                    "Skipping block for private IP: " + ipAddress);
            return false;
        }

        String sql = """
            INSERT OR REPLACE INTO ip_blacklist
            (ip_address, reason, blocked_at, blocked_by, is_active)
            VALUES (?, ?, ?, ?, 1)
            """;
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, ipAddress);
            ps.setString(2, reason);
            ps.setString(3, DateHelper.now());
            ps.setString(4, blockedBy);
            ps.executeUpdate();

            log.security(SOURCE,
                    "IP BLOCKED: " + ipAddress
                            + " | Reason: " + reason
                            + " | By: " + blockedBy);

            // Record in audit log
            auditDAO.insert(new AuditLog(
                    0, DateHelper.now(), blockedBy,
                    AuditLog.Action.IP_BLOCKED,
                    ipAddress, reason, "SECURITY"
            ));
            return true;

        } catch (SQLException e) {
            log.error(SOURCE,
                    "blockIp failed: " + e.getMessage());
            return false;
        }
    }

    // ── Unblock an IP ─────────────────────────────

    /**
     * Removes an IP from the active blacklist.
     * Sets is_active = 0 (keeps audit trail).
     */
    public boolean unblockIp(String ipAddress) {
        String sql = """
            UPDATE ip_blacklist
            SET is_active = 0
            WHERE ip_address = ?
            """;
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, ipAddress);
            int rows = ps.executeUpdate();

            if (rows > 0) {
                log.info(SOURCE, "IP unblocked: " + ipAddress);
                return true;
            }
        } catch (SQLException e) {
            log.error(SOURCE,
                    "unblockIp failed: " + e.getMessage());
        }
        return false;
    }

    // ── Get All Blocked IPs ───────────────────────

    /**
     * Returns all currently active blacklisted IPs.
     */
    public List<String> getBlockedIps() {
        List<String> ips = new ArrayList<>();
        String sql = """
            SELECT ip_address FROM ip_blacklist
            WHERE is_active = 1
            ORDER BY blocked_at DESC
            """;
        try (Connection conn = DBConnection.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {

            while (rs.next()) {
                ips.add(rs.getString("ip_address"));
            }
        } catch (SQLException e) {
            log.error(SOURCE,
                    "getBlockedIps failed: " + e.getMessage());
        }
        return ips;
    }

    // ── Auto Block Critical Threats ───────────────

    /**
     * Automatically blocks IPs with CRITICAL risk score.
     * Called after threat detection completes.
     */
    public void autoBlockCriticalIps(List<String> criticalIps) {
        log.info(SOURCE, "Auto-blocking "
                + criticalIps.size() + " critical IP(s)...");

        for (String ip : criticalIps) {
            blockIp(ip,
                    "Auto-blocked: CRITICAL risk score",
                    "SYSTEM");
        }
    }

    // ── Print Blacklist ───────────────────────────

    /** Prints all currently blocked IPs to console. */
    public void printBlacklist() {
        List<String> blocked = getBlockedIps();
        System.out.println("\n" + "=".repeat(40));
        System.out.println("  IP BLACKLIST");
        System.out.println("=".repeat(40));
        System.out.println("  Total blocked: " + blocked.size());

        if (blocked.isEmpty()) {
            System.out.println("  No IPs currently blocked.");
        } else {
            blocked.forEach(ip ->
                    System.out.println("  🚫 " + ip));
        }
        System.out.println("=".repeat(40) + "\n");
    }
}