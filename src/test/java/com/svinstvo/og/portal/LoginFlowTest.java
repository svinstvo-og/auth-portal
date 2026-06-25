package com.svinstvo.og.portal;

import com.svinstvo.og.portal.service.TotpCredentialService;
import com.svinstvo.og.portal.service.UserService;
import com.svinstvo.og.totp.TotpGenerator;
import com.svinstvo.og.totp.TotpRegistrationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LoginFlowTest {

    @Autowired MockMvc mockMvc;
    @Autowired UserService userService;
    @Autowired TotpCredentialService totpCredentialService;
    @Autowired TotpRegistrationService totpRegistrationService;
    @Autowired TotpGenerator totpGenerator;

    private static final String USERNAME = "frank";
    private static final String PASSWORD = "pass123";

    @BeforeEach
    void setUp() {
        try { userService.register(USERNAME, PASSWORD); } catch (IllegalArgumentException ignored) {}
        String secret = totpRegistrationService.generateSecret();
        totpCredentialService.saveSecret(USERNAME, secret);
    }

    @Test
    void loginPageLoads() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    void wrongPasswordRedirectsToLoginError() throws Exception {
        mockMvc.perform(post("/login").with(csrf())
                        .param("username", USERNAME)
                        .param("password", "wrong"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void correctPasswordRedirectsToSecondFactor() throws Exception {
        mockMvc.perform(post("/login").with(csrf())
                        .param("username", USERNAME)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/second-factor"));
    }

    @Test
    void partiallyAuthenticatedCannotAccessDashboard() throws Exception {
        MvcResult login = mockMvc.perform(post("/login").with(csrf())
                        .param("username", USERNAME).param("password", PASSWORD))
                .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession();

        // Access denied handler redirects PRE_AUTH users to /second-factor
        mockMvc.perform(get("/dashboard").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/second-factor"));
    }

    @Test
    void correctTotpUpgradesToFullAuthAndShowsDashboard() throws Exception {
        MvcResult login = mockMvc.perform(post("/login").with(csrf())
                        .param("username", USERNAME).param("password", PASSWORD))
                .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession();

        String code = totpGenerator.generateCurrent(USERNAME);

        mockMvc.perform(post("/second-factor/totp").with(csrf()).session(session)
                        .param("code", code))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"));

        mockMvc.perform(get("/dashboard").session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("dashboard"));
    }

    @Test
    void wrongTotpCodeStaysOnSecondFactorPage() throws Exception {
        MvcResult login = mockMvc.perform(post("/login").with(csrf())
                        .param("username", USERNAME).param("password", PASSWORD))
                .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession();

        mockMvc.perform(post("/second-factor/totp").with(csrf()).session(session)
                        .param("code", "000000"))
                .andExpect(status().isOk())
                .andExpect(view().name("second-factor"))
                .andExpect(model().attributeExists("error"));
    }

    @Test
    void unauthenticatedUserRedirectedToLogin() throws Exception {
        mockMvc.perform(get("/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    void sessionHasPreAuthRoleAfterPassword() throws Exception {
        MvcResult login = mockMvc.perform(post("/login").with(csrf())
                        .param("username", USERNAME).param("password", PASSWORD))
                .andReturn();

        var session = (MockHttpSession) login.getRequest().getSession();
        var ctx = (org.springframework.security.core.context.SecurityContext)
                session.getAttribute("SPRING_SECURITY_CONTEXT");

        assertThat(ctx).isNotNull();
        assertThat(ctx.getAuthentication().getAuthorities())
                .map(a -> a.getAuthority())
                .contains("ROLE_PRE_AUTH");
    }
}
