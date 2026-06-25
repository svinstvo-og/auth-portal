package com.svinstvo.og.portal.webauthn;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.SessionScope;

/**
 * Session-scoped store for in-flight WebAuthn ceremony state.
 * Each user session holds at most one pending registration and one pending assertion.
 */
@Component
@SessionScope
public class WebAuthnChallengeStore {

    private static final String KEY_REG    = "webauthn_pending_registration";
    private static final String KEY_ASSERT = "webauthn_pending_assertion";

    public void storeRegistration(HttpSession session, PublicKeyCredentialCreationOptions options) {
        session.setAttribute(KEY_REG, options);
    }

    public PublicKeyCredentialCreationOptions getRegistration(HttpSession session) {
        return (PublicKeyCredentialCreationOptions) session.getAttribute(KEY_REG);
    }

    public void removeRegistration(HttpSession session) {
        session.removeAttribute(KEY_REG);
    }

    public void storeAssertion(HttpSession session, AssertionRequest request) {
        session.setAttribute(KEY_ASSERT, request);
    }

    public AssertionRequest getAssertion(HttpSession session) {
        return (AssertionRequest) session.getAttribute(KEY_ASSERT);
    }

    public void removeAssertion(HttpSession session) {
        session.removeAttribute(KEY_ASSERT);
    }
}
