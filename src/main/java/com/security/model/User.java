package com.security.model;

public class User {

    private int id;
    private String username;
    private String email;
    private String role;      // ADMIN, USER, GUEST
    private String createdAt;

    // Constructor
    public User(int id, String username, String email, String role, String createdAt) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.role = role;
        this.createdAt = createdAt;
    }

    // Getters
    public int getId()           { return id; }
    public String getUsername()  { return username; }
    public String getEmail()     { return email; }
    public String getRole()      { return role; }
    public String getCreatedAt() { return createdAt; }

    // Setters
    public void setId(int id)              { this.id = id; }
    public void setUsername(String u)      { this.username = u; }
    public void setEmail(String e)         { this.email = e; }
    public void setRole(String r)          { this.role = r; }
    public void setCreatedAt(String c)     { this.createdAt = c; }

    @Override
    public String toString() {
        return "User{id=" + id + ", username=" + username + ", role=" + role + "}";
    }
}
