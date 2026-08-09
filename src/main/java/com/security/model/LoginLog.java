package com.security.model;

public class LoginLog {

    private int id;
    private String username;
    private String ipAddress;
    private String loginTime;
    private boolean success;
    private String failureReason;
    private String location;

    // Constructor
    public LoginLog(int id, String username, String ipAddress,
                    String loginTime, boolean success,
                    String failureReason, String location) {
        this.id = id;
        this.username = username;
        this.ipAddress = ipAddress;
        this.loginTime = loginTime;
        this.success = success;
        this.failureReason = failureReason;
        this.location = location;
    }

    // Getters
    public int getId()               { return id; }
    public String getUsername()      { return username; }
    public String getIpAddress()     { return ipAddress; }
    public String getLoginTime()     { return loginTime; }
    public boolean isSuccess()       { return success; }
    public String getFailureReason() { return failureReason; }
    public String getLocation()      { return location; }

    // Setters
    public void setId(int id)                  { this.id = id; }
    public void setUsername(String username)    { this.username = username; }
    public void setIpAddress(String ip)        { this.ipAddress = ip; }
    public void setLoginTime(String loginTime)  { this.loginTime = loginTime; }
    public void setSuccess(boolean success)     { this.success = success; }
    public void setFailureReason(String reason) { this.failureReason = reason; }
    public void setLocation(String location)    { this.location = location; }

    @Override
    public String toString() {
        return "LoginLog{user=" + username +
                ", ip=" + ipAddress +
                ", success=" + success +
                ", time=" + loginTime + "}";
    }
}