package io.github.tonyblack10.passkeydemo.model;

import java.time.Instant;

/**
 * Usuário da aplicação.
 *
 * @param userHandle  identificador opaco e aleatório (Base64URL) enviado ao autenticador como
 *                    {@code user.id}. Não deve conter dados pessoais (e-mail, nome etc.)
 * @param username    nome de login, único
 * @param displayName nome exibido pelo autenticador ao escolher a passkey
 * @param createdAt   momento do cadastro
 */
public record UserAccount(String userHandle, String username, String displayName, Instant createdAt) {
}
