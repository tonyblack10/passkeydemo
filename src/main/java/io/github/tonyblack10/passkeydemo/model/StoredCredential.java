package io.github.tonyblack10.passkeydemo.model;

import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Uma passkey registrada. Envolve o {@link CredentialRecordImpl} do webauthn4j, que guarda
 * a chave pública (COSE), o contador de assinaturas, os transportes e as flags de backup,
 * e acrescenta metadados úteis para a interface.
 * <p>
 * Os métodos que alteram estado são {@code synchronized} para que a verificação do contador e
 * a sua atualização aconteçam de forma atômica.
 */
public final class StoredCredential {

    private final String credentialId;
    private final String userHandle;
    private final String username;
    private final String nickname;
    private final CredentialRecordImpl record;
    private final Instant createdAt;
    private Instant lastUsedAt;

    public StoredCredential(String credentialId, String userHandle, String username, String nickname,
                            CredentialRecordImpl record, Instant createdAt) {
        this.credentialId = credentialId;
        this.userHandle = userHandle;
        this.username = username;
        this.nickname = nickname;
        this.record = record;
        this.createdAt = createdAt;
    }

    /** Atualiza o estado após uma autenticação bem-sucedida. */
    public synchronized void markUsed(long newSignCount, boolean userVerified, boolean backedUp, Instant when) {
        record.setCounter(newSignCount);
        record.setBackedUp(backedUp);
        if (userVerified) {
            record.setUvInitialized(true);
        }
        lastUsedAt = when;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getUserHandle() {
        return userHandle;
    }

    public String getUsername() {
        return username;
    }

    public String getNickname() {
        return nickname;
    }

    public CredentialRecordImpl getRecord() {
        return record;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public synchronized Instant getLastUsedAt() {
        return lastUsedAt;
    }

    public synchronized long getSignCount() {
        return record.getCounter();
    }

    public synchronized boolean isBackupEligible() {
        return Boolean.TRUE.equals(record.isBackupEligible());
    }

    public synchronized boolean isBackedUp() {
        return Boolean.TRUE.equals(record.isBackedUp());
    }

    public synchronized boolean isUvInitialized() {
        return Boolean.TRUE.equals(record.isUvInitialized());
    }

    /** Identifica o modelo do autenticador. Fica zerado quando a atestação é {@code none}. */
    public String getAaguid() {
        AAGUID aaguid = record.getAttestedCredentialData().getAaguid();
        return aaguid == null ? "-" : aaguid.toString();
    }

    public String getAlgorithm() {
        COSEAlgorithmIdentifier alg = record.getAttestedCredentialData().getCOSEKey().getAlgorithm();
        return alg == null ? "-" : alg.toString();
    }

    public String getAttestationFormat() {
        return record.getAttestationStatement() == null ? "-" : record.getAttestationStatement().getFormat();
    }

    public List<String> getTransports() {
        Set<AuthenticatorTransport> transports = record.getTransports();
        return transports == null ? List.of() : transports.stream().map(AuthenticatorTransport::getValue).sorted().toList();
    }

    /** Passkeys com BE=1 podem ser sincronizadas (iCloud Keychain, Google Password Manager etc.). */
    public String getKind() {
        return isBackupEligible() ? "Sincronizável" : "Vinculada ao dispositivo";
    }
}
