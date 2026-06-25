package com.svinstvo.og.portal.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "webauthn_credentials")
public class WebAuthnCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "credential_id", unique = true, nullable = false)
    private byte[] credentialId;

    @Column(name = "public_key", nullable = false, columnDefinition = "BYTEA")
    private byte[] publicKey;

    @Column(name = "sign_count", nullable = false)
    private long signCount = 0;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public Long getId()                         { return id; }
    public User getUser()                       { return user; }
    public void setUser(User u)                 { this.user = u; }
    public byte[] getCredentialId()             { return credentialId; }
    public void setCredentialId(byte[] c)       { this.credentialId = c; }
    public byte[] getPublicKey()                { return publicKey; }
    public void setPublicKey(byte[] pk)         { this.publicKey = pk; }
    public long getSignCount()                  { return signCount; }
    public void setSignCount(long sc)           { this.signCount = sc; }
    public Instant getCreatedAt()               { return createdAt; }
}
