package com.svinstvo.og.portal.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/register/**", "/login", "/css/**", "/js/**").permitAll()
                .requestMatchers("/second-factor/**", "/webauthn/**").hasRole("PRE_AUTH")
                .anyRequest().hasRole("USER")
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .successHandler(preAuthSuccessHandler())
                .failureUrl("/login?error")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
            )
            // Disable CSRF for WebAuthn REST endpoints; keep it for form submissions
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/webauthn/**")
            )
            // ROLE_PRE_AUTH users denied access to ROLE_USER pages → send to second-factor
            .exceptionHandling(ex -> ex
                .accessDeniedHandler(preAuthAccessDeniedHandler())
            );

        return http.build();
    }

    /**
     * After successful password verification, grant ROLE_PRE_AUTH and redirect to second-factor page.
     * The full ROLE_USER is only granted after TOTP or WebAuthn verification.
     */
    private AccessDeniedHandler preAuthAccessDeniedHandler() {
        return (request, response, ex) -> {
            String username = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "anonymous";
            log.warn("Access denied for username={}, redirecting to second-factor", username);
            response.sendRedirect("/second-factor");
        };
    }

    private AuthenticationSuccessHandler preAuthSuccessHandler() {
        return (request, response, authentication) -> {
            log.info("Form login succeeded for username={}", authentication.getName());
            response.sendRedirect("/second-factor");
        };
    }
}
