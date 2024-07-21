package io.github.susimsek.springssosamples.security.oauth2.json;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@JsonTypeInfo(use = Id.CLASS)
@JsonDeserialize(using = JWEAlgorithmDeserializer.class)
@JsonAutoDetect(
    fieldVisibility = Visibility.ANY,
    getterVisibility = Visibility.NONE,
    isGetterVisibility = Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class JWEAlgorithmMixin {
    JWEAlgorithmMixin() {
    }
}
