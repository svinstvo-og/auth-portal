package com.svinstvo.og.portal.service;

import com.svinstvo.og.portal.config.WebAuthnProperties;
import com.svinstvo.og.portal.domain.User;
import com.svinstvo.og.portal.domain.WebAuthnCredential;
import com.svinstvo.og.portal.repository.WebAuthnCredentialRepository;
import com.svinstvo.og.portal.webauthn.PortalCredentialRepository;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.ByteBuffer;

@Service
public class WebAuthnService {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnService.class);

    private final RelyingParty relyingParty;
    private final WebAuthnCredentialRepository credentialRepository;
    private final UserService userService;

    public WebAuthnService(WebAuthnProperties props,
                            PortalCredentialRepository portalCredentialRepository,
                            WebAuthnCredentialRepository credentialRepository,
                            UserService userService) {
        this.credentialRepository = credentialRepository;
        this.userService = userService;

        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id(props.getRpId())
                .name(props.getRpName())
                .build();

        this.relyingParty = RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(portalCredentialRepository)
                .origins(java.util.Set.of(props.getOrigin()))
                .build();
    }

    public PublicKeyCredentialCreationOptions startRegistration(String username) {
        User user = userService.findByUsername(username);
        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(username)
                .id(new ByteArray(longToBytes(user.getId())))
                .build();

        return relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(userIdentity)
                        .build());
    }

    @Transactional
    public void finishRegistration(String username,
                                    PublicKeyCredentialCreationOptions options,
                                    PublicKeyCredential<AuthenticatorAttestationResponse,
                                            ClientRegistrationExtensionOutputs> pkc)
            throws RegistrationFailedException {

        RegistrationResult result = relyingParty.finishRegistration(
                FinishRegistrationOptions.builder()
                        .request(options)
                        .response(pkc)
                        .build());

        User user = userService.findByUsername(username);
        WebAuthnCredential cred = new WebAuthnCredential();
        cred.setUser(user);
        cred.setCredentialId(result.getKeyId().getId().getBytes());
        cred.setPublicKey(result.getPublicKeyCose().getBytes());
        cred.setSignCount(result.getSignatureCount());
        credentialRepository.save(cred);
    }

    public AssertionRequest startAssertion(String username) {
        return relyingParty.startAssertion(
                StartAssertionOptions.builder()
                        .username(username)
                        .build());
    }

    @Transactional
    public void finishAssertion(AssertionRequest request,
                                 PublicKeyCredential<AuthenticatorAssertionResponse,
                                         ClientAssertionExtensionOutputs> pkc)
            throws AssertionFailedException {

        AssertionResult result = relyingParty.finishAssertion(
                FinishAssertionOptions.builder()
                        .request(request)
                        .response(pkc)
                        .build());

        if (!result.isSuccess()) {
            throw new AssertionFailedException("Assertion verification failed");
        }

        // Update sign count to defend against cloned authenticators
        credentialRepository.findByCredentialId(result.getCredential().getCredentialId().getBytes())
                .ifPresent(c -> {
                    c.setSignCount(result.getSignatureCount());
                    credentialRepository.save(c);
                });
    }

    private static byte[] longToBytes(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }
}
