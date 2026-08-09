package com.security.model;

public class ThreatAlert {

    private int id;
    private String threatType;   // BRUTE_FORCE, PORT_SCAN, MALWARE, etc.
    private String sourceIp;
    private String targetSystem;
    private String severity;     // LOW, MEDIUM, HIGH, CRITICAL
    private String detectedAt;
    private String status;       // OPEN, RESOLVED, FALSE_POSITIVE
    private double riskScore;    // 0 to 100

    // Constructor
    public ThreatAlert(int id, String threatType, String sourceIp,
                       String targetSystem, String severity,
                       String detectedAt, String status, double riskScore) {
        this.id = id;
        this.threatType = threatType;
        this.sourceIp = sourceIp;
        this.targetSystem = targetSystem;
        this.severity = severity;
        this.detectedAt = detectedAt;
        this.status = status;
        this.riskScore = riskScore;
    }

    // Getters
    public int getId()             { return id; }
    public String getThreatType()  { return threatType; }
    public String getSourceIp()    { return sourceIp; }
    public String getTargetSystem(){ return targetSystem; }
    public String getSeverity()    { return severity; }
    public String getDetectedAt()  { return detectedAt; }
    public String getStatus()      { return status; }
    public double getRiskScore()   { return riskScore; }

    // Setters
    public void setId(int id)                    { this.id = id; }
    public void setThreatType(String threatType)  { this.threatType = threatType; }
    public void setSourceIp(String sourceIp)      { this.sourceIp = sourceIp; }
    public void setTargetSystem(String target)    { this.targetSystem = target; }
    public void setSeverity(String severity)      { this.severity = severity; }
    public void setDetectedAt(String detectedAt)  { this.detectedAt = detectedAt; }
    public void setStatus(String status)          { this.status = status; }
    public void setRiskScore(double riskScore)    { this.riskScore = riskScore; }

    @Override
    public String toString() {
        return "ThreatAlert{type=" + threatType +
                ", ip=" + sourceIp +
                ", severity=" + severity +
                ", score=" + riskScore + "}";
    }
}
