package io.github.tonyblack10.passkeydemo.service;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.util.Base64UrlUtil;
import io.github.tonyblack10.passkeydemo.config.WebAuthnProperties;
import io.github.tonyblack10.passkeydemo.dto.AuthenticationResult;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.CredentialDescriptor;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.RequestOptions;
import io.github.tonyblack10.passkeydemo.model.StoredCredential;
import io.github.tonyblack10.passkeydemo.model.UserAccount;
import io.github.tonyblack10.passkeydemo.repository.InMemoryCredentialRepository;
import io.github.tonyblack10.passkeydemo.repository.InMemoryUserRepository;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static io.github.tonyblack10.passkeydemo.service.WebAuthnSupport.b64;

/**
 * Cerimônia de autenticação (validação de uma passkey), em dois passos:
 * <ol>
 *     <li>{@link #start}: gera o challenge e as opções para {@code navigator.credentials.get()};</li>
 *     <li>{@link #finish}: valida a assinatura com a chave pública guardada no registro.</li>
 * </ol>
 */
@Service
public class AuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    private final WebAuthnManager webAuthnManager;
    private final WebAuthnProperties properties;
    private final InMemoryUserRepository users;
    private final InMemoryCredentialRepository credentials;
    private final ChallengeStore challengeStore;
    private final WebAuthnSupport support;
    private final Clock clock;

    public AuthenticationService(WebAuthnManager webAuthnManager, WebAuthnProperties properties,
                                 InMemoryUserRepository users, InMemoryCredentialRepository credentials,
                                 ChallengeStore challengeStore, WebAuthnSupport support, Clock clock) {
        this.webAuthnManager = webAuthnManager;
        this.properties = properties;
        this.users = users;
        this.credentials = credentials;
        this.challengeStore = challengeStore;
        this.support = support;
        this.clock = clock;
    }

    /**
     * Passo 1: gera as opções de autenticação.
     *
     * @param rawUsername opcional; quando vazio, {@code allowCredentials} fica vazio e o navegador
     *                    oferece as passkeys descobríveis existentes para este rpId
     * @param preference  tipo de autenticador sugerido ao navegador via {@code hints}
     */
    public RequestOptions start(String rawUsername, AuthenticatorPreference preference, HttpSession session) {
        String username = StringUtils.hasText(rawUsername) ? rawUsername.trim().toLowerCase(Locale.ROOT) : null;
        String userHandle = null;
        List<CredentialDescriptor> allow = List.of();

        if (username != null) {
            UserAccount user = users.findByUsername(username).orElseThrow(() -> {
                // Numa aplicação real, evite revelar se o usuário existe (enumeração de usuários).
                log.warn("[AUTENTICAÇÃO 1/2] Usuário '{}' não encontrado", username);
                return new PasskeyException("Usuário não encontrado.");
            });
            userHandle = user.userHandle();
            allow = credentials.findByUserHandle(userHandle).stream().map(support::descriptor).toList();
            if (allow.isEmpty()) {
                log.warn("[AUTENTICAÇÃO 1/2] Usuário '{}' não possui passkeys", username);
                throw new PasskeyException("Este usuário não possui passkeys registradas.");
            }
        }

        byte[] challenge = new DefaultChallenge().getValue();
        challengeStore.save(session, new PendingCeremony(CeremonyType.AUTHENTICATION, challenge, username, null,
                userHandle, null, Instant.now(clock).plus(properties.timeout())));

        log.info("[AUTENTICAÇÃO 1/2] Opções geradas ({}), allowCredentials={}, hints={}",
                username == null ? "sem username - credencial descobrível" : "usuário '" + username + "'",
                allow.size(), preference.hints());
        log.debug("[AUTENTICAÇÃO 1/2] challenge={}", b64(challenge));

        return new RequestOptions(b64(challenge), properties.timeout().toMillis(), properties.rpId(), allow,
                properties.userVerification(), preference.hints(), Map.of());
    }

    /** Passo 2: verifica a assinatura e atualiza o contador. */
    public AuthenticationResult finish(String authenticationResponseJson, HttpSession session) {
        PendingCeremony pending = challengeStore.consume(session, CeremonyType.AUTHENTICATION);

        AuthenticationData data = webAuthnManager.parseAuthenticationResponseJSON(authenticationResponseJson);
        String credentialId = b64(data.getCredentialId());
        log.info("[AUTENTICAÇÃO 2/2] Verificando asserção da credencial {}", credentialId);
        support.logClientData("[AUTENTICAÇÃO 2/2]", data.getCollectedClientData());
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authData = data.getAuthenticatorData();
        support.logAuthenticatorData("[AUTENTICAÇÃO 2/2]", authData);

        StoredCredential credential = credentials.findById(credentialId).orElseThrow(() -> {
            log.warn("[AUTENTICAÇÃO 2/2] Credencial {} desconhecida (removida do servidor?)", credentialId);
            return new PasskeyException("Passkey não reconhecida. Ela pode ter sido removida deste servidor.");
        });
        verifyOwnership(pending, data, credential);

        // Quando o username foi informado, a credencial usada precisa estar entre as permitidas.
        List<byte[]> allowCredentials = pending.userHandle() == null ? null
                : credentials.findByUserHandle(pending.userHandle()).stream()
                .map(c -> Base64UrlUtil.decode(c.getCredentialId()))
                .toList();

        long previousCount;
        synchronized (credential) {
            previousCount = credential.getSignCount();
            // verify: challenge, origem, rpId, flags UP/UV, assinatura com a chave pública guardada
            // e contador (signCount) maior que o anterior, quando o autenticador o implementa.
            AuthenticationParameters parameters = new AuthenticationParameters(
                    support.serverProperty(pending.challenge()),
                    credential.getRecord(),
                    allowCredentials,
                    properties.userVerificationRequired(),
                    true);
            webAuthnManager.verify(data, parameters);
            credential.markUsed(authData.getSignCount(), authData.isFlagUV(), authData.isFlagBS(),
                    Instant.now(clock));
        }

        log.info("[AUTENTICAÇÃO 2/2] Usuário '{}' autenticado com a passkey '{}' (signCount {} -> {}, UV={})",
                credential.getUsername(), credential.getNickname(), previousCount, authData.getSignCount(),
                authData.isFlagUV());
        return new AuthenticationResult(credential.getUsername(), credentialId, authData.getSignCount(),
                authData.isFlagUV(), "Bem-vindo(a), " + credential.getUsername() + "!");
    }

    /** Garante que a credencial pertence ao usuário esperado (userHandle). */
    private void verifyOwnership(PendingCeremony pending, AuthenticationData data, StoredCredential credential) {
        if (pending.userHandle() != null && !pending.userHandle().equals(credential.getUserHandle())) {
            log.warn("[AUTENTICAÇÃO 2/2] Credencial {} não pertence ao usuário '{}'", credential.getCredentialId(),
                    pending.username());
            throw new PasskeyException("Esta passkey não pertence ao usuário informado.");
        }
        byte[] responseUserHandle = data.getUserHandle();
        if (responseUserHandle == null || responseUserHandle.length == 0) {
            // Sem username, o userHandle devolvido pelo autenticador é a única forma de identificar o usuário.
            if (pending.userHandle() == null) {
                log.warn("[AUTENTICAÇÃO 2/2] userHandle ausente em login sem username");
                throw new PasskeyException("O autenticador não informou o usuário. Informe o username.");
            }
            return;
        }
        String userHandle = b64(responseUserHandle);
        if (!userHandle.equals(credential.getUserHandle())) {
            log.warn("[AUTENTICAÇÃO 2/2] userHandle da resposta ({}) difere do dono da credencial ({})", userHandle,
                    credential.getUserHandle());
            throw new PasskeyException("A passkey não corresponde ao usuário.");
        }
        log.debug("[AUTENTICAÇÃO 2/2] userHandle confere com o dono da credencial ('{}')", credential.getUsername());
    }
}
