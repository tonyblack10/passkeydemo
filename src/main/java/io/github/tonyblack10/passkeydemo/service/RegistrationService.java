package io.github.tonyblack10.passkeydemo.service;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.CredentialPropertiesOutput;
import io.github.tonyblack10.passkeydemo.config.WebAuthnProperties;
import io.github.tonyblack10.passkeydemo.dto.RegistrationResult;
import io.github.tonyblack10.passkeydemo.dto.RegistrationStartRequest;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.AuthenticatorSelection;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.CreationOptions;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.CredentialDescriptor;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.CredentialParameter;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.RelyingParty;
import io.github.tonyblack10.passkeydemo.dto.WebAuthnJson.User;
import io.github.tonyblack10.passkeydemo.model.StoredCredential;
import io.github.tonyblack10.passkeydemo.model.UserAccount;
import io.github.tonyblack10.passkeydemo.repository.InMemoryCredentialRepository;
import io.github.tonyblack10.passkeydemo.repository.InMemoryUserRepository;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static io.github.tonyblack10.passkeydemo.service.WebAuthnSupport.b64;

/**
 * Cerimônia de registro (criação de uma passkey), em dois passos:
 * <ol>
 *     <li>{@link #start}: gera o challenge e as opções para {@code navigator.credentials.create()};</li>
 *     <li>{@link #finish}: valida a resposta do autenticador e guarda a chave pública.</li>
 * </ol>
 */
@Service
public class RegistrationService {

    private static final Logger log = LoggerFactory.getLogger(RegistrationService.class);
    private static final int USER_HANDLE_LENGTH = 32;

    private final WebAuthnManager webAuthnManager;
    private final WebAuthnProperties properties;
    private final List<PublicKeyCredentialParameters> pubKeyCredParams;
    private final InMemoryUserRepository users;
    private final InMemoryCredentialRepository credentials;
    private final ChallengeStore challengeStore;
    private final WebAuthnSupport support;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public RegistrationService(WebAuthnManager webAuthnManager, WebAuthnProperties properties,
                               List<PublicKeyCredentialParameters> pubKeyCredParams, InMemoryUserRepository users,
                               InMemoryCredentialRepository credentials, ChallengeStore challengeStore,
                               WebAuthnSupport support, Clock clock) {
        this.webAuthnManager = webAuthnManager;
        this.properties = properties;
        this.pubKeyCredParams = pubKeyCredParams;
        this.users = users;
        this.credentials = credentials;
        this.challengeStore = challengeStore;
        this.support = support;
        this.clock = clock;
    }

    /** Passo 1: gera as opções de criação de credencial. */
    public CreationOptions start(RegistrationStartRequest request, HttpSession session) {
        String username = request.username().trim().toLowerCase(Locale.ROOT);
        UserAccount existing = users.findByUsername(username).orElse(null);

        // O userHandle é aleatório e estável: o mesmo usuário sempre recebe o mesmo user.id.
        String userHandle = existing != null ? existing.userHandle() : newUserHandle();
        String displayName = StringUtils.hasText(request.displayName()) ? request.displayName().trim()
                : existing != null ? existing.displayName() : username;
        String nickname = StringUtils.hasText(request.nickname()) ? request.nickname().trim() : "Passkey";
        AuthenticatorPreference preference = AuthenticatorPreference.from(request.authenticator());
        String attachment = preference.attachment() != null ? preference.attachment()
                : properties.authenticatorAttachmentOrNull();

        // excludeCredentials impede que o mesmo autenticador seja registrado duas vezes para o usuário.
        List<CredentialDescriptor> exclude = existing == null ? List.of()
                : credentials.findByUserHandle(userHandle).stream().map(support::descriptor).toList();

        byte[] challenge = new DefaultChallenge().getValue();
        challengeStore.save(session, new PendingCeremony(CeremonyType.REGISTRATION, challenge, username,
                displayName, userHandle, nickname, Instant.now(clock).plus(properties.timeout())));

        log.info("[REGISTRO 1/2] Opções geradas para '{}' ({}), userHandle={}, credenciais excluídas={}, "
                        + "autenticador={} (attachment={}, hints={})", username,
                existing == null ? "usuário novo" : "usuário existente", userHandle, exclude.size(), preference,
                attachment == null ? "qualquer" : attachment, preference.hints());
        log.debug("[REGISTRO 1/2] challenge={}", b64(challenge));

        return new CreationOptions(
                new RelyingParty(properties.rpId(), properties.rpName()),
                new User(userHandle, username, displayName),
                b64(challenge),
                pubKeyCredParams.stream()
                        .map(p -> new CredentialParameter(p.getType().getValue(), p.getAlg().getValue()))
                        .toList(),
                properties.timeout().toMillis(),
                exclude,
                new AuthenticatorSelection(attachment, properties.residentKey(),
                        properties.requireResidentKey(), properties.userVerification()),
                preference.hints(),
                properties.attestation(),
                // credProps pede ao navegador que informe se a credencial criada é descobrível (rk).
                Map.of("credProps", true));
    }

    /** Passo 2: verifica a resposta do autenticador e persiste a credencial. */
    public RegistrationResult finish(String registrationResponseJson, HttpSession session) {
        PendingCeremony pending = challengeStore.consume(session, CeremonyType.REGISTRATION);
        log.info("[REGISTRO 2/2] Verificando resposta para '{}'", pending.username());

        // parse: decodifica JSON -> clientDataJSON + attestationObject (CBOR). Lança DataConversionException.
        RegistrationData data = webAuthnManager.parseRegistrationResponseJSON(registrationResponseJson);
        support.logClientData("[REGISTRO 2/2]", data.getCollectedClientData());
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authData =
                data.getAttestationObject().getAuthenticatorData();
        support.logAuthenticatorData("[REGISTRO 2/2]", authData);

        // verify: challenge, origem, hash do rpId, flags UP/UV, algoritmo permitido e atestação.
        // Lança uma subclasse de VerificationException (BadChallengeException, BadOriginException...).
        RegistrationParameters parameters = new RegistrationParameters(
                support.serverProperty(pending.challenge()),
                pubKeyCredParams,
                properties.userVerificationRequired(),
                true);
        webAuthnManager.verify(data, parameters);
        log.info("[REGISTRO 2/2] Resposta validada pelo webauthn4j (formato de atestação: {})",
                data.getAttestationObject().getFormat());

        AttestedCredentialData attested = authData.getAttestedCredentialData();
        String credentialId = b64(attested.getCredentialId());
        CredentialPropertiesOutput credProps = data.getClientExtensions() == null ? null
                : data.getClientExtensions().getCredProps();
        log.debug("[REGISTRO 2/2] credentialId={}, AAGUID={}, algoritmo={}, transports={}, credProps.rk={}",
                credentialId, attested.getAaguid(), attested.getCOSEKey().getAlgorithm(), data.getTransports(),
                credProps == null ? "(não informado)" : credProps.getRk());

        UserAccount user = users.saveIfAbsent(new UserAccount(pending.userHandle(), pending.username(),
                pending.displayName(), Instant.now(clock)));
        if (!user.userHandle().equals(pending.userHandle())) {
            // Outro navegador registrou o mesmo username entre o passo 1 e o passo 2.
            log.warn("[REGISTRO 2/2] Username '{}' foi registrado por outra sessão durante a cerimônia",
                    pending.username());
            throw new PasskeyException("O usuário '" + pending.username() + "' acabou de ser criado por outra "
                    + "sessão. Tente novamente.");
        }

        // CredentialRecordImpl guarda tudo o que é necessário para validar autenticações futuras.
        CredentialRecordImpl record = new CredentialRecordImpl(data.getAttestationObject(),
                data.getCollectedClientData(), data.getClientExtensions(), data.getTransports());
        StoredCredential credential = new StoredCredential(credentialId, user.userHandle(), user.username(),
                pending.nickname(), record, Instant.now(clock));
        if (!credentials.saveIfAbsent(credential)) {
            log.warn("[REGISTRO 2/2] credentialId {} já está registrado", credentialId);
            throw new PasskeyException("Esta passkey já está registrada.");
        }

        log.info("[REGISTRO 2/2] Passkey '{}' registrada com sucesso para '{}' ({})", credential.getNickname(),
                user.username(), credential.getKind());
        return new RegistrationResult(user.username(), credentialId, credential.getKind(),
                "Passkey registrada com sucesso para " + user.username() + ".");
    }

    private String newUserHandle() {
        byte[] bytes = new byte[USER_HANDLE_LENGTH];
        random.nextBytes(bytes);
        return b64(bytes);
    }
}
