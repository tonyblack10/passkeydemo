package io.github.tonyblack10.passkeydemo.service;

import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;

/**
 * Guarda o challenge pendente na sessão HTTP. Cada challenge:
 * <ul>
 *     <li>pertence a uma única sessão (o navegador que iniciou a cerimônia);</li>
 *     <li>é consumido uma única vez (removido na leitura), impedindo replay;</li>
 *     <li>expira após o timeout configurado.</li>
 * </ul>
 */
@Component
public class ChallengeStore {

    private static final Logger log = LoggerFactory.getLogger(ChallengeStore.class);
    private static final String ATTRIBUTE_PREFIX = "passkey.pending.";

    private final Clock clock;

    public ChallengeStore(Clock clock) {
        this.clock = clock;
    }

    public void save(HttpSession session, PendingCeremony ceremony) {
        Object previous = session.getAttribute(attributeName(ceremony.type()));
        if (previous != null) {
            log.debug("Substituindo cerimônia {} pendente anterior desta sessão", ceremony.type());
        }
        session.setAttribute(attributeName(ceremony.type()), ceremony);
        log.debug("Cerimônia {} pendente salva na sessão, expira em {}", ceremony.type(), ceremony.expiresAt());
    }

    /**
     * Remove e devolve a cerimônia pendente.
     *
     * @throws PasskeyException se não houver cerimônia pendente ou se ela já tiver expirado
     */
    public PendingCeremony consume(HttpSession session, CeremonyType type) {
        String name = attributeName(type);
        PendingCeremony ceremony = (PendingCeremony) session.getAttribute(name);
        session.removeAttribute(name);
        if (ceremony == null) {
            log.warn("Nenhuma cerimônia {} pendente nesta sessão (challenge já usado, sessão nova ou expirada)", type);
            throw new PasskeyException("Nenhuma operação em andamento. Inicie o processo novamente.");
        }
        if (Instant.now(clock).isAfter(ceremony.expiresAt())) {
            log.warn("Challenge da cerimônia {} expirou em {}", type, ceremony.expiresAt());
            throw new PasskeyException("O tempo para concluir a operação expirou. Tente novamente.");
        }
        log.debug("Cerimônia {} pendente consumida (uso único)", type);
        return ceremony;
    }

    private static String attributeName(CeremonyType type) {
        return ATTRIBUTE_PREFIX + type.name();
    }
}
