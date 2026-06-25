package com.svinstvo.og.portal;

import com.svinstvo.og.portal.repository.TotpCredentialRepository;
import com.svinstvo.og.portal.repository.UserRepository;
import com.svinstvo.og.totp.TotpGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static com.svinstvo.og.portal.controller.RegistrationController.SESSION_TOTP_SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RegistrationFlowTest {

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired TotpCredentialRepository totpCredentialRepository;
    @Autowired TotpGenerator totpGenerator;

    @BeforeEach
    void cleanUp() {
        totpCredentialRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void registerFormLoads() throws Exception {
        mockMvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"));
    }

    @Test
    void successfulRegistrationRedirectsToTotpSetup() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("username", "alice")
                        .param("password", "password123"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/register/totp-setup"));

        assertThat(userRepository.findByUsername("alice")).isPresent();
    }

    @Test
    void duplicateUsernameShowsError() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                .param("username", "alice").param("password", "p1"));
        mockMvc.perform(post("/register").with(csrf())
                        .param("username", "alice").param("password", "p2"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(model().attributeExists("error"));
    }

    @Test
    void totpSetupPageRendersQrImage() throws Exception {
        MvcResult reg = mockMvc.perform(post("/register").with(csrf())
                        .param("username", "bob").param("password", "pass"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) reg.getRequest().getSession();

        mockMvc.perform(get("/register/totp-setup").session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("totp-setup"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("totp-setup/qr")));
    }

    @Test
    void qrEndpointReturnsPng() throws Exception {
        MvcResult reg = mockMvc.perform(post("/register").with(csrf())
                        .param("username", "carol").param("password", "pass"))
                .andReturn();
        MockHttpSession session = (MockHttpSession) reg.getRequest().getSession();

        byte[] png = mockMvc.perform(get("/register/totp-setup/qr").session(session))
                .andExpect(status().isOk())
                .andExpect(content().contentType(org.springframework.http.MediaType.IMAGE_PNG))
                .andReturn().getResponse().getContentAsByteArray();

        assertThat(png[0]).isEqualTo((byte) 0x89);
        assertThat(png[1]).isEqualTo((byte) 'P');
    }

    @Test
    void wrongTotpCodeDuringSetupShowsError() throws Exception {
        MvcResult reg = mockMvc.perform(post("/register").with(csrf())
                        .param("username", "dave").param("password", "pass"))
                .andReturn();
        MockHttpSession session = (MockHttpSession) reg.getRequest().getSession();

        mockMvc.perform(post("/register/totp-setup").with(csrf()).session(session)
                        .param("code", "000000"))
                .andExpect(status().isOk())
                .andExpect(view().name("totp-setup"))
                .andExpect(model().attributeExists("error"));
    }

    @Test
    void correctTotpCodeCompletesTotpSetup() throws Exception {
        MvcResult reg = mockMvc.perform(post("/register").with(csrf())
                        .param("username", "eve").param("password", "pass"))
                .andReturn();
        MockHttpSession session = (MockHttpSession) reg.getRequest().getSession();

        String secret = (String) session.getAttribute(SESSION_TOTP_SECRET);

        // Generate the current code directly from the session secret
        com.svinstvo.og.totp.SecretProvider tempProvider = id -> secret;
        com.svinstvo.og.totp.TotpProperties props = new com.svinstvo.og.totp.TotpProperties();
        com.svinstvo.og.totp.TotpGenerator gen = new com.svinstvo.og.totp.TotpGenerator(tempProvider, props);
        String code = gen.generateCurrent("_");

        mockMvc.perform(post("/register/totp-setup").with(csrf()).session(session)
                        .param("code", code))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?registered"));

        Long eveId = userRepository.findByUsername("eve").orElseThrow().getId();
        assertThat(totpCredentialRepository.findByUserId(eveId)).isPresent();
    }
}
