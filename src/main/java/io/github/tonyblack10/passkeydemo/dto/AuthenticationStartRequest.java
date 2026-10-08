package io.github.tonyblack10.passkeydemo.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * @param username      opcional. Vazio = login sem username, usando uma credencial descobrível.
 * @param authenticator opcional: {@code any}, {@code platform}, {@code security-key} ou {@code hybrid}
 */
public record AuthenticationStartRequest(
        @Size(max = 64) String username,
        @Pattern(regexp = "any|platform|security-key|hybrid", message = "Tipo de autenticador inválido")
        String authenticator) {
}
