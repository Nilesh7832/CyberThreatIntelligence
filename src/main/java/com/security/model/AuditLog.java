package com.security.model;

/**
 * AuditLog - Records every important system action.
 * Industry requirement: full audit trail of who did what and when.
 * Used for compliance, forensics, and debugging.
 */
public class AuditLog {

    // Action types allowed in the system
    public enum Action {
        LOGIN_SUCCESS,
        LOGIN_FAILED,
        THREAT_DETECTED,
        IP_BLOCKED,
        RISK_SCORED,
        REPORT_GENERATED,
        MODEL_TRAINED,
        SYSTEM_START,
        SYSTEM_STOP
    }

    private int    id;
    private String timestamp;    // When it happened
    private String actor;        // Who did it (IP or username)
    private Action action;       // What happened
    private String target;       // What was affected
    private String details;      // Extra info
    private String severity;     // INFO / WARN / ERROR / SECURITY

    // ── Constructor ──────────────────────────────
    public AuditLog(int id, String timestamp, String actor,
                    Action action, String target,
                    String details, String severity) {
        this.id        = id;
        this.timestamp = timestamp;
        this.actor     = actor;
        this.action    = action;
        this.target    = target;
        this.details   = details;
        this.severity  = severity;
    }

    // ── Getters ──────────────────────────────────
    public int    getId()        { return id; }
    public String getTimestamp() { return timestamp; }
    public String getActor()     { return actor; }
    public Action getAction()    { return action; }
    public String getTarget()    { return target; }
    public String getDetails()   { return details; }
    public String getSeverity()  { return severity; }

    // ── Setters ──────────────────────────────────
    public void setId(int id)              { this.id = id; }
    public void setTimestamp(String t)     { this.timestamp = t; }
    public void setActor(String actor)     { this.actor = actor; }
    public void setAction(Action action)   { this.action = action; }
    public void setTarget(String target)   { this.target = target; }
    public void setDetails(String details) { this.details = details; }
    public void setSeverity(String s)      { this.severity = s; }

    // ── toString ─────────────────────────────────
    @Override
    public String toString() {
        return String.format(
                "AuditLog{time=%s, actor=%s, action=%s, target=%s}",
                timestamp, actor, action.name(), target);
    }
}