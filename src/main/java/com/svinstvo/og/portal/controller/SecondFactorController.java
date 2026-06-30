package com.svinstvo.og.portal.controller;

import com.svinstvo.og.portal.service.SecondFactorService;
import com.svinstvo.og.totp.TotpVerifier;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/second-factor")
public class SecondFactorController {

    private static final Logger log = LoggerFactory.getLogger(SecondFactorController.class);

    private final TotpVerifier totpVerifier;
    private final SecondFactorService secondFactorService;

    public SecondFactorController(TotpVerifier totpVerifier,
                                   SecondFactorService secondFactorService) {
        this.totpVerifier = totpVerifier;
        this.secondFactorService = secondFactorService;
    }

    @PostMapping("/totp")
    public String verifyTotp(@RequestParam String code,
                              Authentication authentication,
                              HttpServletRequest request,
                              HttpServletResponse response,
                              Model model) {
        String username = authentication.getName();

        boolean verified;
        try {
            verified = totpVerifier.verify(username, code);
        } catch (IllegalStateException e) {
            log.error("TOTP verification error for username={}: {}", username, e.getMessage());
            model.addAttribute("error", "TOTP is not configured for this account — please contact support");
            return "second-factor";
        }

        if (!verified) {
            log.warn("TOTP second factor failed for username={}", username);
            model.addAttribute("error", "Invalid code — please try again");
            return "second-factor";
        }

        log.info("TOTP second factor passed for username={}", username);
        secondFactorService.upgradeToFullAuth(username, request, response);
        return "redirect:/dashboard";
    }
}
