package com.svinstvo.og.portal.controller;

import com.svinstvo.og.portal.repository.WebAuthnCredentialRepository;
import com.svinstvo.og.portal.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final UserService userService;
    private final WebAuthnCredentialRepository credentialRepository;

    public DashboardController(UserService userService, WebAuthnCredentialRepository credentialRepository) {
        this.userService = userService;
        this.credentialRepository = credentialRepository;
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, Model model) {
        String username = authentication.getName();
        model.addAttribute("username", username);
        long userId = userService.findByUsername(username).getId();
        model.addAttribute("hasPasskey", !credentialRepository.findByUserId(userId).isEmpty());
        return "dashboard";
    }
}
