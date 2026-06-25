package com.svinstvo.og.portal.repository;

import com.svinstvo.og.portal.domain.WebAuthnCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredential, Long> {
    List<WebAuthnCredential> findByUserId(Long userId);

    default Optional<WebAuthnCredential> findByCredentialId(byte[] credentialId) {
        return findAll().stream()
                .filter(c -> Arrays.equals(c.getCredentialId(), credentialId))
                .findFirst();
    }
}
