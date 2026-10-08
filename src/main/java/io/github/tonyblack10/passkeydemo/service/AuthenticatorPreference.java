package io.github.tonyblack10.passkeydemo.service;

import java.util.List;
import java.util.Locale;

/**
 * Tipo de autenticador escolhido na interface. Traduz para {@code authenticatorAttachment}
 * (restrição) e {@code hints} (dica de interface do WebAuthn nível 3).
 * <p>
 * Sem uma preferência, navegadores como Chrome e Safari no macOS abrem direto o Touch ID /
 * iCloud Keychain; as outras opções ficam escondidas em "Outras opções".
 */
public enum AuthenticatorPreference {

    /** Usa o {@code passkey.authenticator-attachment} configurado e deixa o navegador decidir. */
    ANY(null, List.of()),
    /** Autenticador embutido: Touch ID, Windows Hello, sensor do Android. */
    PLATFORM("platform", List.of("client-device")),
    /** Chave de segurança física (YubiKey etc.) via USB/NFC. */
    SECURITY_KEY("cross-platform", List.of("security-key")),
    /** Celular ou tablet via QR code + Bluetooth. */
    HYBRID("cross-platform", List.of("hybrid"));

    private final String attachment;
    private final List<String> hints;

    AuthenticatorPreference(String attachment, List<String> hints) {
        this.attachment = attachment;
        this.hints = hints;
    }

    public String attachment() {
        return attachment;
    }

    public List<String> hints() {
        return hints;
    }

    /** Converte o valor do formulário ({@code any}, {@code platform}, {@code security-key}, {@code hybrid}). */
    public static AuthenticatorPreference from(String value) {
        if (value == null || value.isBlank()) {
            return ANY;
        }
        return valueOf(value.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
    }
}
