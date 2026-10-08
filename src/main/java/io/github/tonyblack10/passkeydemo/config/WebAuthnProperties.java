package io.github.tonyblack10.passkeydemo.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

/**
 * Configurações da Relying Party (RP) lidas do prefixo {@code passkey.*} em
 * {@code application.properties}. Cada opção está explicada em detalhes no arquivo PASSKEYS.md.
 *
 * @param rpId                    domínio ao qual as passkeys ficam vinculadas (ex.: {@code exemplo.com.br})
 * @param rpName                  nome amigável da aplicação exibido pelo navegador/autenticador
 * @param origins                 origens (esquema + host + porta) aceitas no clientDataJSON
 * @param timeout                 tempo que o navegador espera pelo usuário e validade do challenge no servidor
 * @param userVerification        {@code required}, {@code preferred} ou {@code discouraged}
 * @param residentKey             {@code required}, {@code preferred} ou {@code discouraged} (credencial descobrível)
 * @param attestation             {@code none}, {@code indirect}, {@code direct} ou {@code enterprise}
 * @param authenticatorAttachment vazio (qualquer), {@code platform} ou {@code cross-platform}
 * @param algorithms              identificadores COSE aceitos, em ordem de preferência (-7 ES256, -8 EdDSA, -257 RS256)
 */
@Validated
@ConfigurationProperties(prefix = "passkey")
public record WebAuthnProperties(
        @NotBlank String rpId,
        @NotBlank String rpName,
        @NotEmpty List<String> origins,
        @NotNull @DefaultValue("60s") Duration timeout,
        @DefaultValue("preferred") @Pattern(regexp = "required|preferred|discouraged") String userVerification,
        @DefaultValue("preferred") @Pattern(regexp = "required|preferred|discouraged") String residentKey,
        @DefaultValue("none") @Pattern(regexp = "none|indirect|direct|enterprise") String attestation,
        @Pattern(regexp = "|platform|cross-platform") String authenticatorAttachment,
        @NotEmpty @DefaultValue({"-7", "-8", "-257"}) List<Long> algorithms) {

    /** UV só é exigida pelo servidor quando configurada como {@code required}. */
    public boolean userVerificationRequired() {
        return "required".equals(userVerification);
    }

    /** {@code requireResidentKey} existe por compatibilidade com WebAuthn nível 1. */
    public boolean requireResidentKey() {
        return "required".equals(residentKey);
    }

    /** Devolve {@code null} quando não configurado, para que o campo seja omitido do JSON. */
    public String authenticatorAttachmentOrNull() {
        return StringUtils.hasText(authenticatorAttachment) ? authenticatorAttachment : null;
    }
}
