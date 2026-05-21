package com.auth.service.logger;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.LayoutBase;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class CustomLogLayout extends LayoutBase<ILoggingEvent> {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
            .withZone(ZoneId.systemDefault());

    @Override
    public String doLayout(ILoggingEvent event) {
        StringBuilder sb = new StringBuilder();

        // Append timestamp
        sb.append(FORMATTER.format(Instant.ofEpochMilli(event.getTimeStamp())));
        sb.append("  ");

        // Append log level
        sb.append(event.getLevel().toString());
        sb.append(" : ");

        // Append log message
        sb.append(event.getFormattedMessage());
        sb.append("\n");

        return sb.toString();
    }
}