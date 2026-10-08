package io.github.tonyblack10.passkeydemo.repository;

import io.github.tonyblack10.passkeydemo.model.UserAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Armazena usuários em memória. Os dados se perdem ao reiniciar a aplicação.
 */
@Repository
public class InMemoryUserRepository {

    private static final Logger log = LoggerFactory.getLogger(InMemoryUserRepository.class);

    private final Map<String, UserAccount> byUsername = new ConcurrentHashMap<>();
    private final Map<String, UserAccount> byUserHandle = new ConcurrentHashMap<>();

    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(byUsername.get(username));
    }

    public Optional<UserAccount> findByUserHandle(String userHandle) {
        return Optional.ofNullable(byUserHandle.get(userHandle));
    }

    /**
     * Salva o usuário se o username ainda não existir.
     *
     * @return o usuário já existente, ou o recém-salvo
     */
    public UserAccount saveIfAbsent(UserAccount user) {
        UserAccount current = byUsername.putIfAbsent(user.username(), user);
        if (current != null) {
            return current;
        }
        byUserHandle.put(user.userHandle(), user);
        log.info("Usuário '{}' criado (userHandle={})", user.username(), user.userHandle());
        return user;
    }

    public int count() {
        return byUsername.size();
    }
}
