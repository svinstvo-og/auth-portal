package com.svinstvo.og.portal.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "totp_credentials")
public class TotpCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 64)
    private String secret;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public Long getId()             { return id; }
    public User getUser()           { return user; }
    public void setUser(User u)     { this.user = u; }
    public String getSecret()       { return secret; }
    public void setSecret(String s) { this.secret = s; }
    public Instant getCreatedAt()   { return createdAt; }
}
