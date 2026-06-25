package com.svinstvo.og.portal.repository;

import com.svinstvo.og.portal.domain.TotpCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TotpCredentialRepository extends JpaRepository<TotpCredential, Long> {
    Optional<TotpCredential> findByUserId(Long userId);
}
