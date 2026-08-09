package com.security.model;

/**
 * RiskScore - Represents an ML-calculated risk score for an IP.
 * Stores all contributing factors for full audit trail.
 */
public class RiskScore {

    private int    id;
    private String ipAddress;
    private double totalScore;      // Final score 0-100
    private String riskLevel;       // LOW / MEDIUM / HIGH / CRITICAL
    private int    failCount;       // Number of failed logins
    private double geoRisk;         // Geographic risk factor
    private double timeRisk;        // Time-of-day risk factor
    private double speedRisk;       // Attack speed risk factor
    private String mlPrediction;    // Weka model prediction
    private String calculatedAt;    // Timestamp of calculation

    // ── Constructor ──────────────────────────────
    public RiskScore(int id, String ipAddress, double totalScore,
                     String riskLevel, int failCount, double geoRisk,
                     double timeRisk, double speedRisk,
                     String mlPrediction, String calculatedAt) {
        this.id            = id;
        this.ipAddress     = ipAddress;
        this.totalScore    = totalScore;
        this.riskLevel     = riskLevel;
        this.failCount     = failCount;
        this.geoRisk       = geoRisk;
        this.timeRisk      = timeRisk;
        this.speedRisk     = speedRisk;
        this.mlPrediction  = mlPrediction;
        this.calculatedAt  = calculatedAt;
    }

    // ── Getters ──────────────────────────────────
    public int    getId()           { return id; }
    public String getIpAddress()    { return ipAddress; }
    public double getTotalScore()   { return totalScore; }
    public String getRiskLevel()    { return riskLevel; }
    public int    getFailCount()    { return failCount; }
    public double getGeoRisk()      { return geoRisk; }
    public double getTimeRisk()     { return timeRisk; }
    public double getSpeedRisk()    { return speedRisk; }
    public String getMlPrediction() { return mlPrediction; }
    public String getCalculatedAt() { return calculatedAt; }

    // ── Setters ──────────────────────────────────
    public void setId(int id)                    { this.id = id; }
    public void setIpAddress(String ipAddress)   { this.ipAddress = ipAddress; }
    public void setTotalScore(double totalScore) { this.totalScore = totalScore; }
    public void setRiskLevel(String riskLevel)   { this.riskLevel = riskLevel; }
    public void setFailCount(int failCount)       { this.failCount = failCount; }
    public void setGeoRisk(double geoRisk)       { this.geoRisk = geoRisk; }
    public void setTimeRisk(double timeRisk)     { this.timeRisk = timeRisk; }
    public void setSpeedRisk(double speedRisk)   { this.speedRisk = speedRisk; }
    public void setMlPrediction(String ml)       { this.mlPrediction = ml; }
    public void setCalculatedAt(String at)       { this.calculatedAt = at; }

    // ── toString ─────────────────────────────────
    @Override
    public String toString() {
        return String.format(
                "RiskScore{ip=%s, score=%.1f, level=%s, prediction=%s}",
                ipAddress, totalScore, riskLevel, mlPrediction);
    }
}