package io.github.tonyblack10.passkeydemo.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

/**
 * Estruturas JSON trocadas com o navegador. Seguem o formato JSON definido no WebAuthn
 * nível 3 ({@code PublicKeyCredentialCreationOptionsJSON} / {@code PublicKeyCredentialRequestOptionsJSON}):
 * todo campo binário (challenge, user.id, credential id) trafega como Base64URL.
 */
public final class WebAuthnJson {

    private WebAuthnJson() {
    }

    /** Opções para {@code navigator.credentials.create()} (registro). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CreationOptions(
            RelyingParty rp,
            User user,
            String challenge,
            List<CredentialParameter> pubKeyCredParams,
            long timeout,
            List<CredentialDescriptor> excludeCredentials,
            AuthenticatorSelection authenticatorSelection,
            List<String> hints,
            String attestation,
            Map<String, Object> extensions) {
    }

    /** Opções para {@code navigator.credentials.get()} (autenticação). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RequestOptions(
            String challenge,
            long timeout,
            String rpId,
            List<CredentialDescriptor> allowCredentials,
            String userVerification,
            List<String> hints,
            Map<String, Object> extensions) {
    }

    public record RelyingParty(String id, String name) {
    }

    public record User(String id, String name, String displayName) {
    }

    public record CredentialParameter(String type, long alg) {
    }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record CredentialDescriptor(String type, String id, List<String> transports) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AuthenticatorSelection(
            String authenticatorAttachment,
            String residentKey,
            boolean requireResidentKey,
            String userVerification) {
    }
}
