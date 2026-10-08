package io.github.tonyblack10.passkeydemo.dto;

public record AuthenticationResult(String username, String credentialId, long signCount, boolean userVerified,
                                   String message) {
}
