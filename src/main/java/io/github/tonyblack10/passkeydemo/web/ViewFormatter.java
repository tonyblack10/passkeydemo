package io.github.tonyblack10.passkeydemo.web;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Formatação usada nos templates: {@code ${@fmt.dateTime(...)}}.
 */
@Component("fmt")
public class ViewFormatter {

    private static final DateTimeFormatter DATE_TIME =
            DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss").withZone(ZoneId.systemDefault());

    public String dateTime(Instant instant) {
        return instant == null ? "nunca" : DATE_TIME.format(instant);
    }

    /** Encurta IDs longos para exibição: primeiros e últimos caracteres. */
    public String shorten(String value) {
        if (value == null || value.length() <= 16) {
            return value;
        }
        return value.substring(0, 8) + "…" + value.substring(value.length() - 6);
    }
}
