package com.svinstvo.og.portal;

import com.svinstvo.og.portal.service.TotpCredentialService;
import com.svinstvo.og.portal.service.UserService;
import com.svinstvo.og.totp.TotpRegistrationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class WebAuthnFlowTest {

    @Autowired MockMvc mockMvc;
    @Autowired UserService userService;
    @Autowired TotpCredentialService totpCredentialService;
    @Autowired TotpRegistrationService totpRegistrationService;

    private static final String USERNAME = "grace";
    private static final String PASSWORD = "pass123";

    @BeforeEach
    void setUp() {
        try { userService.register(USERNAME, PASSWORD); } catch (IllegalArgumentException ignored) {}
        String secret = totpRegistrationService.generateSecret();
        totpCredentialService.saveSecret(USERNAME, secret);
    }

    private MockHttpSession partiallyAuthenticatedSession() throws Exception {
        MvcResult login = mockMvc.perform(post("/login").with(csrf())
                        .param("username", USERNAME).param("password", PASSWORD))
                .andReturn();
        return (MockHttpSession) login.getRequest().getSession();
    }

    @Test
    void registrationStartRequiresPreAuth() throws Exception {
        // Unauthenticated → should be redirected
        mockMvc.perform(post("/webauthn/register/start"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void registrationStartReturnsJsonChallenge() throws Exception {
        MockHttpSession session = partiallyAuthenticatedSession();

        MvcResult result = mockMvc.perform(post("/webauthn/register/start").session(session))
                .andExpect(status().isOk())
                .andReturn();

        String json = result.getResponse().getContentAsString();
        assertThat(json).contains("challenge");
        assertThat(json).contains("rp");
        assertThat(json).contains("user");
    }

    @Test
    void registrationFinishWithMalformedBodyReturnsBadRequest() throws Exception {
        MockHttpSession session = partiallyAuthenticatedSession();
        // Start first to set up session state
        mockMvc.perform(post("/webauthn/register/start").session(session));

        mockMvc.perform(post("/webauthn/register/finish").session(session)
                        .contentType("application/json")
                        .content("{\"invalid\":true}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void assertionStartRequiresPreAuth() throws Exception {
        mockMvc.perform(post("/webauthn/authenticate/start"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void assertionStartReturnsJsonChallenge() throws Exception {
        MockHttpSession session = partiallyAuthenticatedSession();

        MvcResult result = mockMvc.perform(post("/webauthn/authenticate/start").session(session))
                .andExpect(status().isOk())
                .andReturn();

        String json = result.getResponse().getContentAsString();
        assertThat(json).contains("challenge");
    }

    @Test
    void assertionFinishWithMalformedBodyReturnsBadRequest() throws Exception {
        MockHttpSession session = partiallyAuthenticatedSession();
        mockMvc.perform(post("/webauthn/authenticate/start").session(session));

        mockMvc.perform(post("/webauthn/authenticate/finish").session(session)
                        .contentType("application/json")
                        .content("{\"invalid\":true}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void assertionFinishWithoutStartReturnsBadRequest() throws Exception {
        MockHttpSession session = partiallyAuthenticatedSession();
        // No /authenticate/start — session has no pending assertion
        mockMvc.perform(post("/webauthn/authenticate/finish").session(session)
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }
}
