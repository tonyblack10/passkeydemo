package io.github.tonyblack10.passkeydemo.web;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.verifier.exception.VerificationException;
import io.github.tonyblack10.passkeydemo.service.PasskeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/**
 * Converte exceções da API em respostas RFC 9457 (Problem Details).
 * Os detalhes técnicos vão para o log; o usuário recebe uma mensagem clara e sem dados sensíveis.
 */
@RestControllerAdvice(assignableTypes = PasskeyApiController.class)
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(PasskeyException.class)
    public ProblemDetail handlePasskey(PasskeyException e) {
        return problem(HttpStatus.BAD_REQUEST, "Operação não permitida", e.getMessage());
    }

    /** JSON malformado ou com campos binários inválidos. */
    @ExceptionHandler(DataConversionException.class)
    public ProblemDetail handleDataConversion(DataConversionException e) {
        log.warn("Resposta do autenticador não pôde ser decodificada: {}", e.getMessage());
        return problem(HttpStatus.BAD_REQUEST, "Resposta inválida",
                "A resposta enviada pelo navegador está malformada.");
    }

    /** Falhas de verificação: challenge, origem, rpId, assinatura, contador, flags... */
    @ExceptionHandler(VerificationException.class)
    public ProblemDetail handleVerification(VerificationException e) {
        log.warn("Verificação WebAuthn falhou: {} - {}", e.getClass().getSimpleName(), e.getMessage());
        return problem(HttpStatus.BAD_REQUEST, "Verificação falhou",
                "A passkey não pôde ser validada (" + e.getClass().getSimpleName() + ").");
    }

    @ExceptionHandler(WebAuthnException.class)
    public ProblemDetail handleWebAuthn(WebAuthnException e) {
        log.warn("Erro WebAuthn: {} - {}", e.getClass().getSimpleName(), e.getMessage());
        return problem(HttpStatus.BAD_REQUEST, "Erro WebAuthn", "Não foi possível processar a passkey.");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException e) {
        String detail = e.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getDefaultMessage())
                .collect(Collectors.joining("; "));
        log.debug("Requisição inválida: {}", detail);
        return problem(HttpStatus.BAD_REQUEST, "Dados inválidos", detail);
    }

    private static ProblemDetail problem(HttpStatus status, String title, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(title);
        return problem;
    }
}
