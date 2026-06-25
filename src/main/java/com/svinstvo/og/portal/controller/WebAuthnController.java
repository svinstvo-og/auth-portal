package com.svinstvo.og.portal.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.svinstvo.og.portal.service.SecondFactorService;
import com.svinstvo.og.portal.service.WebAuthnService;
import com.svinstvo.og.portal.webauthn.WebAuthnChallengeStore;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/webauthn")
public class WebAuthnController {

    private final WebAuthnService webAuthnService;
    private final WebAuthnChallengeStore challengeStore;
    private final SecondFactorService secondFactorService;
    private final ObjectMapper objectMapper;

    public WebAuthnController(WebAuthnService webAuthnService,
                               WebAuthnChallengeStore challengeStore,
                               SecondFactorService secondFactorService,
                               ObjectMapper objectMapper) {
        this.webAuthnService = webAuthnService;
        this.challengeStore = challengeStore;
        this.secondFactorService = secondFactorService;
        this.objectMapper = objectMapper;
    }

    // ── Registration ceremony ─────────────────────────────────────────────────

    @PostMapping("/register/start")
    public ResponseEntity<String> registrationStart(Authentication auth,
                                                     HttpSession session) throws IOException {
        var options = webAuthnService.startRegistration(auth.getName());
        challengeStore.storeRegistration(session, options);
        return ResponseEntity.ok(options.toCredentialsCreateJson());
    }

    @PostMapping("/register/finish")
    public ResponseEntity<Map<String, String>> registrationFinish(
            @RequestBody String body,
            Authentication auth,
            HttpSession session) {

        var options = challengeStore.getRegistration(session);
        if (options == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "No pending registration"));
        }

        try {
            var pkc = PublicKeyCredential.parseRegistrationResponseJson(body);
            webAuthnService.finishRegistration(auth.getName(), options, pkc);
            challengeStore.removeRegistration(session);
            return ResponseEntity.ok(Map.of("status", "registered"));
        } catch (IOException | RegistrationFailedException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ── Authentication ceremony ────────────────────────────────────────────────

    @PostMapping("/authenticate/start")
    public ResponseEntity<String> assertionStart(Authentication auth,
                                                  HttpSession session) throws IOException {
        AssertionRequest request = webAuthnService.startAssertion(auth.getName());
        challengeStore.storeAssertion(session, request);
        return ResponseEntity.ok(request.toCredentialsGetJson());
    }

    @PostMapping("/authenticate/finish")
    public ResponseEntity<Map<String, String>> assertionFinish(
            @RequestBody String body,
            Authentication auth,
            HttpSession session,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        AssertionRequest request = challengeStore.getAssertion(session);
        if (request == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "No pending assertion"));
        }

        try {
            var pkc = PublicKeyCredential.parseAssertionResponseJson(body);
            webAuthnService.finishAssertion(request, pkc);
            challengeStore.removeAssertion(session);
            secondFactorService.upgradeToFullAuth(auth.getName(), httpRequest, httpResponse);
            return ResponseEntity.ok(Map.of("status", "authenticated"));
        } catch (IOException | AssertionFailedException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
