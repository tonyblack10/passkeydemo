package io.github.tonyblack10.passkeydemo.web;

import io.github.tonyblack10.passkeydemo.config.WebAuthnProperties;
import io.github.tonyblack10.passkeydemo.repository.InMemoryCredentialRepository;
import io.github.tonyblack10.passkeydemo.repository.InMemoryUserRepository;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.SessionAttribute;

/**
 * Páginas Thymeleaf e fragmentos HTML trocados pelo htmx.
 */
@Controller
public class PageController {

    private static final Logger log = LoggerFactory.getLogger(PageController.class);

    private final WebAuthnProperties properties;
    private final InMemoryUserRepository users;
    private final InMemoryCredentialRepository credentials;

    public PageController(WebAuthnProperties properties, InMemoryUserRepository users,
                          InMemoryCredentialRepository credentials) {
        this.properties = properties;
        this.users = users;
        this.credentials = credentials;
    }

    @GetMapping("/")
    public String index(@SessionAttribute(name = SessionKeys.AUTHENTICATED_USER, required = false) String currentUser,
                        Model model) {
        model.addAttribute("rp", properties);
        model.addAttribute("currentUser", currentUser);
        return "index";
    }

    /** Lista de passkeys (recarregada pelo htmx quando o evento {@code credentialsChanged} ocorre). */
    @GetMapping("/fragments/credentials")
    public String credentialList(@SessionAttribute(name = SessionKeys.AUTHENTICATED_USER, required = false)
                                 String currentUser, Model model) {
        model.addAttribute("credentials", credentials.findAll());
        model.addAttribute("userCount", users.count());
        model.addAttribute("currentUser", currentUser);
        return "fragments/credentials :: list";
    }

    /** Indicador de sessão (recarregado pelo htmx quando o evento {@code sessionChanged} ocorre). */
    @GetMapping("/fragments/session")
    public String session(@SessionAttribute(name = SessionKeys.AUTHENTICATED_USER, required = false)
                          String currentUser, Model model) {
        model.addAttribute("currentUser", currentUser);
        return "fragments/session :: status";
    }

    /**
     * Remove uma passkey do servidor. Atenção: o autenticador do usuário continua guardando a chave
     * privada; ela apenas deixa de ser aceita aqui. Numa aplicação real esta operação exigiria
     * autenticação, autorização e proteção CSRF.
     */
    @DeleteMapping("/credentials/{credentialId}")
    public String deleteCredential(@PathVariable String credentialId,
                                   @SessionAttribute(name = SessionKeys.AUTHENTICATED_USER, required = false)
                                   String currentUser, Model model) {
        if (credentials.delete(credentialId).isEmpty()) {
            log.warn("Tentativa de remover credencial inexistente {}", credentialId);
        }
        return credentialList(currentUser, model);
    }

    @PostMapping("/logout")
    public String logout(HttpSession session, Model model) {
        Object user = session.getAttribute(SessionKeys.AUTHENTICATED_USER);
        session.invalidate();
        log.info("Usuário '{}' saiu (sessão invalidada)", user);
        model.addAttribute("currentUser", null);
        return "fragments/session :: status";
    }
}
