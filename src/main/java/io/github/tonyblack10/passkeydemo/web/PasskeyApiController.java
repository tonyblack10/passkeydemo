package io.github.tonyblack10.passkeydemo.web;

import io.github.tonyblack10.passkeydemo.dto.AuthenticationResult;
import io.github.tonyblack10.passkeydemo.dto.AuthenticationStartRequest;
import io.github.tonyblack10.passkeydemo.dto.RegistrationResult;
import io.github.tonyblack10.passkeydemo.dto.RegistrationStartRequest;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.CreationOptions;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.RequestOptions;
import io.github.tonyblack10.passkeydemo.service.AuthenticationService;
import io.github.tonyblack10.passkeydemo.service.AuthenticatorPreference;
import io.github.tonyblack10.passkeydemo.service.RegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * API JSON consumida pelo {@code passkey.js}. Cada cerimônia tem dois endpoints:
 * {@code /options} (gera o challenge) e {@code /verify} (valida a resposta do autenticador).
 */
@RestController
@RequestMapping(path = "/api/passkeys", produces = MediaType.APPLICATION_JSON_VALUE)
public class PasskeyApiController {

    private final RegistrationService registrationService;
    private final AuthenticationService authenticationService;

    public PasskeyApiController(RegistrationService registrationService,
                                AuthenticationService authenticationService) {
        this.registrationService = registrationService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/registration/options")
    public CreationOptions registrationOptions(@Valid @RequestBody RegistrationStartRequest request,
                                               HttpSession session) {
        return registrationService.start(request, session);
    }

    /**
     * Recebe o JSON bruto de {@code PublicKeyCredential.toJSON()}; o webauthn4j faz o parse.
     */
    @PostMapping(path = "/registration/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public RegistrationResult registrationVerify(@RequestBody String registrationResponseJson,
                                                 HttpSession session) {
        return registrationService.finish(registrationResponseJson, session);
    }

    @PostMapping("/authentication/options")
    public RequestOptions authenticationOptions(@Valid @RequestBody(required = false) AuthenticationStartRequest request,
                                                HttpSession session) {
        if (request == null) {
            return authenticationService.start(null, AuthenticatorPreference.ANY, session);
        }
        return authenticationService.start(request.username(), AuthenticatorPreference.from(request.authenticator()),
                session);
    }

    @PostMapping(path = "/authentication/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public AuthenticationResult authenticationVerify(@RequestBody String authenticationResponseJson,
                                                     HttpServletRequest request) {
        AuthenticationResult result = authenticationService.finish(authenticationResponseJson, request.getSession());
        // Troca o ID da sessão após o login para evitar ataques de fixação de sessão.
        request.changeSessionId();
        request.getSession().setAttribute(SessionKeys.AUTHENTICATED_USER, result.username());
        return result;
    }
}
