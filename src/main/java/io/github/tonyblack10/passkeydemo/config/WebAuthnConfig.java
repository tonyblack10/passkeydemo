package io.github.tonyblack10.passkeydemo.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;

import java.time.Clock;
import java.util.List;

/**
 * Cria os objetos do webauthn4j como beans do Spring.
 */
@Configuration
@EnableConfigurationProperties(WebAuthnProperties.class)
public class WebAuthnConfig {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnConfig.class);

    private final WebAuthnProperties properties;

    public WebAuthnConfig(WebAuthnProperties properties) {
        this.properties = properties;
    }

    /**
     * Conversor JSON/CBOR do webauthn4j (Jackson 3). É thread-safe e deve ser reutilizado.
     */
    @Bean
    public ObjectConverter webAuthnObjectConverter() {
        return new ObjectConverter();
    }

    /**
     * O "non-strict" aceita qualquer formato de atestação sem validar a cadeia de certificados
     * do fabricante. É o adequado para passkeys de consumidor (atestação {@code none}).
     * <p>
     * Para exigir autenticadores certificados, troque por um {@code new WebAuthnManager(...)}
     * com os {@code AttestationStatementVerifier}s desejados e um
     * {@code DefaultCertPathTrustworthinessVerifier} alimentado por um {@code TrustAnchorRepository}
     * (por exemplo, o FIDO Metadata Service). Veja a seção correspondente em PASSKEYS.md.
     */
    @Bean
    public WebAuthnManager webAuthnManager(ObjectConverter webAuthnObjectConverter) {
        return WebAuthnManager.createNonStrictWebAuthnManager(webAuthnObjectConverter);
    }

    /**
     * Algoritmos de assinatura aceitos, na ordem de preferência. Usado tanto para montar as
     * opções enviadas ao navegador quanto para validar a resposta do registro.
     */
    @Bean
    public List<PublicKeyCredentialParameters> publicKeyCredentialParameters() {
        return properties.algorithms().stream()
                .map(alg -> new PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(alg)))
                .toList();
    }

    /** Relógio injetável, facilita testes de expiração de challenge. */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void logConfiguration() {
        log.info("Relying Party configurada: rpId='{}', rpName='{}', origens={}", properties.rpId(),
                properties.rpName(), properties.origins());
        log.info("Políticas: userVerification={}, residentKey={}, attestation={}, authenticatorAttachment={}, "
                        + "algoritmos={}, timeout={}", properties.userVerification(), properties.residentKey(),
                properties.attestation(), properties.authenticatorAttachmentOrNull() == null ? "(qualquer)"
                        : properties.authenticatorAttachment(), properties.algorithms(), properties.timeout());
    }
}
