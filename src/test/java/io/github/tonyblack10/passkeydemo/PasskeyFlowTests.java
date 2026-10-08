package io.github.tonyblack10.passkeydemo;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorAssertionResponse;
import com.webauthn4j.data.AuthenticatorAttestationResponse;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.PublicKeyCredential;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.ResidentKeyRequirement;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.authenticator.webauthn.NoneAttestationAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Testa os fluxos completos usando o autenticador emulado do módulo webauthn4j-test,
 * que faz o papel do navegador + autenticador.
 */
@SpringBootTest
@AutoConfigureMockMvc
class PasskeyFlowTests {

    private static final Origin ORIGIN = new Origin("http://localhost:8080");

    @Autowired
    private MockMvc mvc;

    private final JsonMapper json = JsonMapper.builder().build();
    private final ObjectConverter converter = new ObjectConverter();
    private ClientPlatform browser;

    @BeforeEach
    void setUp() {
        browser = new ClientPlatform(ORIGIN, new WebAuthnAuthenticatorAdaptor(new NoneAttestationAuthenticator()));
    }

    @Test
    void registersAndAuthenticatesWithUsername() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String credentialId = register(session, "alice");

        JsonNode options = postJson(session, "/api/passkeys/authentication/options", "{\"username\":\"alice\"}");
        String assertion = authenticate(options);

        mvc.perform(post("/api/passkeys/authentication/verify").session(session)
                        .contentType(MediaType.APPLICATION_JSON).content(assertion))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.credentialId").value(credentialId));

        mvc.perform(get("/fragments/credentials"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("alice")));
    }

    @Test
    void authenticatesWithoutUsername() throws Exception {
        MockHttpSession session = new MockHttpSession();
        register(session, "bob");

        JsonNode options = postJson(session, "/api/passkeys/authentication/options", "{}");
        String assertion = authenticate(options);

        mvc.perform(post("/api/passkeys/authentication/verify").session(session)
                        .contentType(MediaType.APPLICATION_JSON).content(assertion))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("bob"));
    }

    @Test
    void rejectsReplayOfTheSameAssertion() throws Exception {
        MockHttpSession session = new MockHttpSession();
        register(session, "carol");
        String assertion = authenticate(postJson(session, "/api/passkeys/authentication/options",
                "{\"username\":\"carol\"}"));

        mvc.perform(post("/api/passkeys/authentication/verify").session(session)
                .contentType(MediaType.APPLICATION_JSON).content(assertion)).andExpect(status().isOk());
        // O challenge é de uso único: reenviar a mesma resposta precisa falhar.
        mvc.perform(post("/api/passkeys/authentication/verify").session(session)
                        .contentType(MediaType.APPLICATION_JSON).content(assertion))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsResponseFromAnotherOrigin() throws Exception {
        MockHttpSession session = new MockHttpSession();
        JsonNode options = postJson(session, "/api/passkeys/registration/options", "{\"username\":\"mallory\"}");
        browser.setOrigin(new Origin("https://phishing.example"));

        mvc.perform(post("/api/passkeys/registration/verify").session(session)
                        .contentType(MediaType.APPLICATION_JSON).content(createCredential(options)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value(containsString("BadOriginException")));
    }

    @Test
    void rejectsVerifyWithoutPendingChallenge() throws Exception {
        mvc.perform(post("/api/passkeys/registration/verify").session(new MockHttpSession())
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Operação não permitida"));
    }

    @Test
    void sendsAttachmentAndHintsForTheChosenAuthenticator() throws Exception {
        mvc.perform(post("/api/passkeys/registration/options").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dave\",\"authenticator\":\"security-key\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticatorSelection.authenticatorAttachment").value("cross-platform"))
                .andExpect(jsonPath("$.hints[0]").value("security-key"));

        mvc.perform(post("/api/passkeys/registration/options").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dave\",\"authenticator\":\"any\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticatorSelection.authenticatorAttachment").doesNotExist())
                .andExpect(jsonPath("$.hints").isEmpty());

        mvc.perform(post("/api/passkeys/authentication/options").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"authenticator\":\"hybrid\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.hints[0]").value("hybrid"));
    }

    @Test
    void rejectsInvalidUsername() throws Exception {
        mvc.perform(post("/api/passkeys/registration/options").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Dados inválidos"));
    }

    // ------------------------------------------------------------------ helpers

    private String register(MockHttpSession session, String username) throws Exception {
        JsonNode options = postJson(session, "/api/passkeys/registration/options",
                "{\"username\":\"" + username + "\",\"nickname\":\"Emulador\"}");
        MvcResult result = mvc.perform(post("/api/passkeys/registration/verify").session(session)
                        .contentType(MediaType.APPLICATION_JSON).content(createCredential(options)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andReturn();
        return json.readTree(result.getResponse().getContentAsString()).get("credentialId").asString();
    }

    private JsonNode postJson(MockHttpSession session, String url, String body) throws Exception {
        MvcResult result = mvc.perform(post(url).session(session).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andReturn();
        return json.readTree(result.getResponse().getContentAsString());
    }

    /** Converte as opções JSON do servidor, chama o emulador e serializa como o navegador faria. */
    private String createCredential(JsonNode o) {
        List<PublicKeyCredentialParameters> params = new ArrayList<>();
        o.get("pubKeyCredParams").forEach(p -> params.add(new PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(p.get("alg").asLong()))));
        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(o.at("/rp/id").asString(), o.at("/rp/name").asString()),
                new PublicKeyCredentialUserEntity(Base64UrlUtil.decode(o.at("/user/id").asString()),
                        o.at("/user/name").asString(), o.at("/user/displayName").asString()),
                new DefaultChallenge(Base64UrlUtil.decode(o.get("challenge").asString())),
                params,
                o.get("timeout").asLong(),
                List.of(),
                new AuthenticatorSelectionCriteria(null, ResidentKeyRequirement.REQUIRED,
                        UserVerificationRequirement.PREFERRED),
                null,
                null);
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential =
                browser.create(options);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("clientDataJSON", Base64UrlUtil.encodeToString(credential.getResponse().getClientDataJSON()));
        response.put("attestationObject",
                Base64UrlUtil.encodeToString(credential.getResponse().getAttestationObject()));
        response.put("transports", List.of("internal"));
        return toJson(credential.getId(), credential.getRawId(), response);
    }

    private String authenticate(JsonNode o) {
        List<PublicKeyCredentialDescriptor> allow = new ArrayList<>();
        if (o.has("allowCredentials")) {
            o.get("allowCredentials").forEach(c -> allow.add(new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY, Base64UrlUtil.decode(c.get("id").asString()), null)));
        }
        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions(
                new DefaultChallenge(Base64UrlUtil.decode(o.get("challenge").asString())),
                o.get("timeout").asLong(),
                o.get("rpId").asString(),
                allow,
                UserVerificationRequirement.PREFERRED,
                null);
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential =
                browser.get(options);

        AuthenticatorAssertionResponse r = credential.getResponse();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("clientDataJSON", Base64UrlUtil.encodeToString(r.getClientDataJSON()));
        response.put("authenticatorData", Base64UrlUtil.encodeToString(r.getAuthenticatorData()));
        response.put("signature", Base64UrlUtil.encodeToString(r.getSignature()));
        if (r.getUserHandle() != null) {
            response.put("userHandle", Base64UrlUtil.encodeToString(r.getUserHandle()));
        }
        return toJson(credential.getId(), credential.getRawId(), response);
    }

    private String toJson(String id, byte[] rawId, Map<String, Object> response) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", id);
        body.put("rawId", Base64UrlUtil.encodeToString(rawId));
        body.put("type", "public-key");
        body.put("response", response);
        body.put("clientExtensionResults", Map.of());
        return converter.getJsonConverter().writeValueAsString(body);
    }
}
