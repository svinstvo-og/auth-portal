package com.svinstvo.og.portal.service;

import com.svinstvo.og.portal.domain.TotpCredential;
import com.svinstvo.og.portal.domain.User;
import com.svinstvo.og.portal.repository.TotpCredentialRepository;
import com.svinstvo.og.totp.SecretProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TotpCredentialService implements SecretProvider {

    private final TotpCredentialRepository credentialRepository;
    private final UserService userService;

    public TotpCredentialService(TotpCredentialRepository credentialRepository,
                                  UserService userService) {
        this.credentialRepository = credentialRepository;
        this.userService = userService;
    }

    @Transactional
    public void saveSecret(String username, String base32Secret) {
        User user = userService.findByUsername(username);
        TotpCredential credential = credentialRepository.findByUserId(user.getId())
                .orElseGet(TotpCredential::new);
        credential.setUser(user);
        credential.setSecret(base32Secret);
        credentialRepository.save(credential);
    }

    @Override
    public String getSecret(String username) {
        User user = userService.findByUsername(username);
        return credentialRepository.findByUserId(user.getId())
                .map(TotpCredential::getSecret)
                .orElseThrow(() -> new IllegalStateException("No TOTP secret for user: " + username));
    }
}
