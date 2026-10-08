package io.github.tonyblack10.passkeydemo.dto;

public record RegistrationResult(String username, String credentialId, String kind, String message) {
}
