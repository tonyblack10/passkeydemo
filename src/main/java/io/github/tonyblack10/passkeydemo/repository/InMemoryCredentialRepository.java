package io.github.tonyblack10.passkeydemo.repository;

import io.github.tonyblack10.passkeydemo.model.StoredCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Armazena as passkeys em memória, indexadas pelo credentialId em Base64URL.
 */
@Repository
public class InMemoryCredentialRepository {

    private static final Logger log = LoggerFactory.getLogger(InMemoryCredentialRepository.class);

    private final Map<String, StoredCredential> byId = new ConcurrentHashMap<>();

    /**
     * @return {@code false} se já existir uma credencial com o mesmo ID
     */
    public boolean saveIfAbsent(StoredCredential credential) {
        boolean saved = byId.putIfAbsent(credential.getCredentialId(), credential) == null;
        if (saved) {
            log.info("Credencial {} salva para o usuário '{}' (total: {})", credential.getCredentialId(),
                    credential.getUsername(), byId.size());
        }
        return saved;
    }

    public Optional<StoredCredential> findById(String credentialId) {
        return Optional.ofNullable(byId.get(credentialId));
    }

    public List<StoredCredential> findByUserHandle(String userHandle) {
        return byId.values().stream()
                .filter(c -> c.getUserHandle().equals(userHandle))
                .sorted(Comparator.comparing(StoredCredential::getCreatedAt))
                .toList();
    }

    public List<StoredCredential> findAll() {
        return byId.values().stream()
                .sorted(Comparator.comparing(StoredCredential::getUsername)
                        .thenComparing(StoredCredential::getCreatedAt))
                .toList();
    }

    public Optional<StoredCredential> delete(String credentialId) {
        StoredCredential removed = byId.remove(credentialId);
        if (removed != null) {
            log.info("Credencial {} do usuário '{}' removida (total: {})", credentialId, removed.getUsername(),
                    byId.size());
        }
        return Optional.ofNullable(removed);
    }
}
