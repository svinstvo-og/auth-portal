package com.svinstvo.og.portal.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SecondFactorService {

    private static final Logger log = LoggerFactory.getLogger(SecondFactorService.class);

    /**
     * Upgrades the current session from ROLE_PRE_AUTH to ROLE_USER.
     * Called after a successful second factor (TOTP or WebAuthn).
     */
    public void upgradeToFullAuth(String username, HttpServletRequest request,
                                   HttpServletResponse response) {
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        var fullAuth = UsernamePasswordAuthenticationToken.authenticated(username, null, authorities);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(fullAuth);
        SecurityContextHolder.setContext(context);

        // Persist the upgraded context back into the HTTP session
        new HttpSessionSecurityContextRepository()
                .saveContext(context, request, response);

        log.info("Upgraded username={} to ROLE_USER", username);
    }
}
