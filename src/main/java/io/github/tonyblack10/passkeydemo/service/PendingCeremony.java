package io.github.tonyblack10.passkeydemo.service;

import java.io.Serializable;
import java.time.Instant;

/**
 * Estado guardado entre a geração das opções (passo 1) e a verificação da resposta (passo 2).
 *
 * @param challenge   bytes aleatórios que o autenticador assina; impedem ataques de replay
 * @param username    usuário envolvido (pode ser {@code null} no login sem username)
 * @param displayName apenas no registro
 * @param userHandle  user.id em Base64URL (pode ser {@code null} no login sem username)
 * @param nickname    apelido da passkey, apenas no registro
 * @param expiresAt   após este instante o challenge não é mais aceito
 */
public record PendingCeremony(
        CeremonyType type,
        byte[] challenge,
        String username,
        String displayName,
        String userHandle,
        String nickname,
        Instant expiresAt) implements Serializable {
}
