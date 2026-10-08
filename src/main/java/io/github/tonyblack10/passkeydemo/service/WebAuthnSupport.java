package io.github.tonyblack10.passkeydemo.service;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import io.github.tonyblack10.passkeydemo.config.WebAuthnProperties;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.CredentialDescriptor;
import io.github.tonyblack10.passkeydemo.model.StoredCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Funções compartilhadas pelos fluxos de registro e autenticação.
 */
@Component
public class WebAuthnSupport {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnSupport.class);

    private final WebAuthnProperties properties;
    private final Set<Origin> origins;

    public WebAuthnSupport(WebAuthnProperties properties) {
        this.properties = properties;
        this.origins = properties.origins().stream().map(Origin::create).collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Monta o {@link ServerProperty}: o que o servidor <em>espera</em> encontrar na resposta.
     * O webauthn4j compara origem, hash do rpId e challenge com o que veio do navegador.
     */
    public ServerProperty serverProperty(byte[] challenge) {
        return ServerProperty.builder()
                .origins(origins)
                .rpId(properties.rpId())
                .challenge(new DefaultChallenge(challenge))
                .build();
    }

    public CredentialDescriptor descriptor(StoredCredential credential) {
        return new CredentialDescriptor("public-key", credential.getCredentialId(), credential.getTransports());
    }

    /** Registra em log o conteúdo do clientDataJSON — útil para diagnosticar erros de origem/challenge. */
    public void logClientData(String step, CollectedClientData clientData) {
        if (clientData == null || !log.isDebugEnabled()) {
            return;
        }
        log.debug("{} clientDataJSON: type={}, origin={}, challenge={}, crossOrigin={}", step,
                clientData.getType(), clientData.getOrigin(),
                Base64UrlUtil.encodeToString(clientData.getChallenge().getValue()), clientData.getCrossOrigin());
    }

    /** Registra em log as flags do authenticatorData e o contador. */
    public void logAuthenticatorData(String step, AuthenticatorData<?> data) {
        if (data == null || !log.isDebugEnabled()) {
            return;
        }
        log.debug("{} authenticatorData: UP(presença)={}, UV(verificação)={}, BE(backup elegível)={}, "
                        + "BS(backup feito)={}, AT(dados de credencial)={}, ED(extensões)={}, signCount={}", step,
                data.isFlagUP(), data.isFlagUV(), data.isFlagBE(), data.isFlagBS(), data.isFlagAT(),
                data.isFlagED(), data.getSignCount());
    }

    public static String b64(byte[] bytes) {
        return Base64UrlUtil.encodeToString(bytes);
    }
}
