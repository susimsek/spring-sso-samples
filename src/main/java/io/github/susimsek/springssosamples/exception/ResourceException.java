package io.github.susimsek.springssosamples.exception;

import lombok.Getter;
import org.springframework.http.HttpStatusCode;

@Getter
public class ResourceException extends RuntimeException {
    private final String errorCode;
    private final HttpStatusCode status;
    private final String resourceName;
    private final String searchCriteria;
    private final transient Object searchValue;

    public ResourceException(String errorCode, String message, HttpStatusCode status,
                             String resourceName, String searchCriteria, Object searchValue) {
        super(message);
        this.errorCode = errorCode;
        this.status = status;
        this.resourceName = resourceName;
        this.searchCriteria = searchCriteria;
        this.searchValue = searchValue;
    }
}
