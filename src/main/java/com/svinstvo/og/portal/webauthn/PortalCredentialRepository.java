package com.svinstvo.og.portal.webauthn;

import com.svinstvo.og.portal.domain.User;
import com.svinstvo.og.portal.domain.WebAuthnCredential;
import com.svinstvo.og.portal.repository.UserRepository;
import com.svinstvo.og.portal.repository.WebAuthnCredentialRepository;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Bridges the JPA credential store to Yubico's CredentialRepository interface.
 * User handle = the user's Long ID packed into 8 bytes (big-endian).
 */
@Component
public class PortalCredentialRepository implements CredentialRepository {

    private final WebAuthnCredentialRepository credRepo;
    private final UserRepository userRepo;

    public PortalCredentialRepository(WebAuthnCredentialRepository credRepo,
                                       UserRepository userRepo) {
        this.credRepo = credRepo;
        this.userRepo = userRepo;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return userRepo.findByUsername(username)
                .map(u -> credRepo.findByUserId(u.getId()))
                .orElse(List.of())
                .stream()
                .map(c -> PublicKeyCredentialDescriptor.builder()
                        .id(new ByteArray(c.getCredentialId()))
                        .build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return userRepo.findByUsername(username)
                .map(u -> new ByteArray(longToBytes(u.getId())));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        long id = bytesToLong(userHandle.getBytes());
        return userRepo.findById(id).map(User::getUsername);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return credRepo.findByCredentialId(credentialId.getBytes())
                .map(c -> toRegistered(c, userHandle));
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return credRepo.findByCredentialId(credentialId.getBytes())
                .map(c -> {
                    ByteArray handle = new ByteArray(longToBytes(c.getUser().getId()));
                    return toRegistered(c, handle);
                })
                .map(Set::of)
                .orElse(Set.of());
    }

    private RegisteredCredential toRegistered(WebAuthnCredential c, ByteArray userHandle) {
        return RegisteredCredential.builder()
                .credentialId(new ByteArray(c.getCredentialId()))
                .userHandle(userHandle)
                .publicKeyCose(new ByteArray(c.getPublicKey()))
                .signatureCount(c.getSignCount())
                .build();
    }

    private static byte[] longToBytes(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    private static long bytesToLong(byte[] bytes) {
        return ByteBuffer.wrap(bytes).getLong();
    }
}
