package io.github.susimsek.springssosamples.logging.formatter;

import io.github.susimsek.springssosamples.logging.model.HttpLog;
import io.github.susimsek.springssosamples.logging.model.MethodLog;

public interface LogFormatter {
    String format(HttpLog httpLog);

    String format(MethodLog methodLog);
}
