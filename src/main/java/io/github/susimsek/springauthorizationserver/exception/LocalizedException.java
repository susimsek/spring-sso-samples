package io.github.susimsek.springauthorizationserver.exception;

import java.util.Map;
import lombok.Getter;
import org.springframework.http.HttpStatusCode;

@Getter
public class LocalizedException extends RuntimeException {
    private final String errorCode;
    private final transient Object[] args;
    private final Map<String, Object> namedArgs;
    private final HttpStatusCode status;

    public LocalizedException(String errorCode,
                              String message, HttpStatusCode status) {
        super(message);
        this.errorCode = errorCode;
        this.status = status;
        this.args = null;
        this.namedArgs = null;
    }

    public LocalizedException(String errorCode,
                              String message,
                              HttpStatusCode status,
                              Object... args) {
        super(message);
        this.errorCode = errorCode;
        this.status = status;
        this.args = args;
        this.namedArgs = null;
    }

    public LocalizedException(String errorCode, String message,
                              HttpStatusCode status,
                              Map<String, Object> namedArgs) {
        super(message);
        this.errorCode = errorCode;
        this.status = status;
        this.args = null;
        this.namedArgs = namedArgs;
    }
}
