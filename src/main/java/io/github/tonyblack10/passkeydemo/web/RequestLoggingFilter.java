package io.github.tonyblack10.passkeydemo.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Coloca um {@code requestId} no MDC (Mapped Diagnostic Context), para que todas as linhas de
 * log de uma requisição possam ser correlacionadas, e registra método, caminho, status e duração.
 * <p>
 * O ID de sessão é registrado apenas parcialmente: o valor completo é uma credencial.
 */
@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingFilter.class);
    private static final String REQUEST_ID = "requestId";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/js/") || path.startsWith("/actuator") || path.equals("/favicon.ico");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String requestId = UUID.randomUUID().toString().substring(0, 8);
        MDC.put(REQUEST_ID, requestId);
        response.setHeader("X-Request-Id", requestId);
        long start = System.nanoTime();
        try {
            log.debug("--> {} {} (sessão {})", request.getMethod(), request.getRequestURI(), sessionHint(request));
            chain.doFilter(request, response);
        } finally {
            log.debug("<-- {} {} status={} em {} ms", request.getMethod(), request.getRequestURI(),
                    response.getStatus(), (System.nanoTime() - start) / 1_000_000);
            MDC.remove(REQUEST_ID);
        }
    }

    private static String sessionHint(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? "nova" : session.getId().substring(0, Math.min(6, session.getId().length())) + "…";
    }
}
