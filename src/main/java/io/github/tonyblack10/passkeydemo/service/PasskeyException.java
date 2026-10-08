package io.github.tonyblack10.passkeydemo.service;

/**
 * Erro de regra de negócio nos fluxos de passkey (challenge expirado, usuário desconhecido etc.).
 * A mensagem é segura para ser exibida ao usuário.
 */
public class PasskeyException extends RuntimeException {

    public PasskeyException(String message) {
        super(message);
    }
}
