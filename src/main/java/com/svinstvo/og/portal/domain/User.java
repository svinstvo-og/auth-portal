package com.svinstvo.og.portal.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 100)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public Long getId()                     { return id; }
    public String getUsername()             { return username; }
    public void setUsername(String u)       { this.username = u; }
    public String getPassword()             { return password; }
    public void setPassword(String p)       { this.password = p; }
    public boolean isEnabled()              { return enabled; }
    public void setEnabled(boolean e)       { this.enabled = e; }
    public Instant getCreatedAt()           { return createdAt; }
}
