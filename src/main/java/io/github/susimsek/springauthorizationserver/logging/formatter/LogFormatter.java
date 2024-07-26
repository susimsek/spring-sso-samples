package io.github.susimsek.springauthorizationserver.logging.formatter;

import io.github.susimsek.springauthorizationserver.logging.model.HttpLog;
import io.github.susimsek.springauthorizationserver.logging.model.MethodLog;

public interface LogFormatter {
    String format(HttpLog httpLog);

    String format(MethodLog methodLog);
}
