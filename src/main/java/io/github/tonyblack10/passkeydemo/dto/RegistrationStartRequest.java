package io.github.tonyblack10.passkeydemo.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegistrationStartRequest(
        @NotBlank(message = "Informe o nome de usuário")
        @Size(max = 64, message = "O nome de usuário deve ter no máximo 64 caracteres")
        @Pattern(regexp = "[A-Za-z0-9._@-]+", message = "Use apenas letras, números, '.', '_', '-' e '@'")
        String username,
        @Size(max = 64, message = "O nome de exibição deve ter no máximo 64 caracteres")
        String displayName,
        @Size(max = 64, message = "O apelido deve ter no máximo 64 caracteres")
        String nickname,
        @Pattern(regexp = "any|platform|security-key|hybrid", message = "Tipo de autenticador inválido")
        String authenticator) {
}
