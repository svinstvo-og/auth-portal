package com.svinstvo.og.portal.controller;

import com.svinstvo.og.portal.service.TotpCredentialService;
import com.svinstvo.og.portal.service.UserService;
import com.svinstvo.og.totp.TotpRegistrationService;
import com.svinstvo.og.totp.TotpVerifier;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/register")
public class RegistrationController {

    private static final Logger log = LoggerFactory.getLogger(RegistrationController.class);

    public static final String SESSION_TOTP_USERNAME = "totp_reg_username";
    public static final String SESSION_TOTP_SECRET   = "totp_reg_secret";

    private final UserService userService;
    private final TotpCredentialService totpCredentialService;
    private final TotpRegistrationService totpRegistrationService;
    private final TotpVerifier totpVerifier;

    public RegistrationController(UserService userService,
                                   TotpCredentialService totpCredentialService,
                                   TotpRegistrationService totpRegistrationService,
                                   TotpVerifier totpVerifier) {
        this.userService = userService;
        this.totpCredentialService = totpCredentialService;
        this.totpRegistrationService = totpRegistrationService;
        this.totpVerifier = totpVerifier;
    }

    @GetMapping
    public String showRegisterForm() {
        return "register";
    }

    @PostMapping
    public String processRegister(@RequestParam String username,
                                   @RequestParam String password,
                                   HttpSession session,
                                   Model model) {
        log.info("Registration attempt for username={}", username);
        try {
            userService.register(username, password);
        } catch (IllegalArgumentException e) {
            log.warn("Registration failed, username already taken: {}", username);
            model.addAttribute("error", e.getMessage());
            return "register";
        }

        log.info("User created, starting TOTP enrollment for username={}", username);
        // Generate TOTP secret and store in session for the enrollment step
        String secret = totpRegistrationService.generateSecret();
        session.setAttribute(SESSION_TOTP_USERNAME, username);
        session.setAttribute(SESSION_TOTP_SECRET, secret);

        return "redirect:/register/totp-setup";
    }

    @GetMapping("/totp-setup")
    public String showTotpSetup(HttpSession session, Model model) {
        String username = (String) session.getAttribute(SESSION_TOTP_USERNAME);
        String secret   = (String) session.getAttribute(SESSION_TOTP_SECRET);
        if (username == null || secret == null) {
            return "redirect:/register";
        }

        String uri = totpRegistrationService.buildOtpAuthUri("AuthPortal", username, secret);
        model.addAttribute("secret", secret);
        model.addAttribute("otpAuthUri", uri);
        return "totp-setup";
    }

    @GetMapping("/totp-setup/qr")
    public ResponseEntity<byte[]> qrCode(HttpSession session) {
        String secret   = (String) session.getAttribute(SESSION_TOTP_SECRET);
        String username = (String) session.getAttribute(SESSION_TOTP_USERNAME);
        if (secret == null || username == null) {
            return ResponseEntity.badRequest().build();
        }
        String uri  = totpRegistrationService.buildOtpAuthUri("AuthPortal", username, secret);
        byte[] png  = totpRegistrationService.generateQrPng(uri, 250, 250);
        return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(png);
    }

    @PostMapping("/totp-setup")
    public String verifyTotpSetup(@RequestParam String code,
                                   HttpSession session,
                                   Model model) {
        String username = (String) session.getAttribute(SESSION_TOTP_USERNAME);
        String secret   = (String) session.getAttribute(SESSION_TOTP_SECRET);
        if (username == null || secret == null) {
            return "redirect:/register";
        }

        // Temporarily wire the session secret for verification
        if (!verifyWithSecret(secret, code)) {
            log.warn("TOTP enrollment verification failed for username={}", username);
            model.addAttribute("error", "Invalid code — please try again");
            String uri = totpRegistrationService.buildOtpAuthUri("AuthPortal", username, secret);
            model.addAttribute("secret", secret);
            model.addAttribute("otpAuthUri", uri);
            return "totp-setup";
        }

        totpCredentialService.saveSecret(username, secret);
        session.removeAttribute(SESSION_TOTP_USERNAME);
        session.removeAttribute(SESSION_TOTP_SECRET);
        log.info("Registration complete, TOTP enrolled for username={}", username);

        return "redirect:/login?registered";
    }

    /** Verify a TOTP code against a raw Base32 secret (before it is persisted). */
    private boolean verifyWithSecret(String base32Secret, String code) {
        // Build a one-shot SecretProvider backed by the session secret
        com.svinstvo.og.totp.SecretProvider tempProvider = id -> base32Secret;
        com.svinstvo.og.totp.TotpProperties props = new com.svinstvo.og.totp.TotpProperties();
        com.svinstvo.og.totp.TotpVerifier tempVerifier =
                new com.svinstvo.og.totp.TotpVerifier(tempProvider, props);
        return tempVerifier.verify("_", code);
    }
}
