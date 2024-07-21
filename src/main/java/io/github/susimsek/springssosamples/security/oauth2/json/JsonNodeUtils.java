//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package io.github.susimsek.springssosamples.security.oauth2.json;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.Set;

abstract class JsonNodeUtils {
    static final TypeReference<Set<String>> STRING_SET = new TypeReference<Set<String>>() {
    };
    static final TypeReference<Map<String, Object>> STRING_OBJECT_MAP = new TypeReference<Map<String, Object>>() {
    };

    JsonNodeUtils() {
    }

    static String findStringValue(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return null;
        } else {
            JsonNode value = jsonNode.findValue(fieldName);
            return value != null && value.isTextual() ? value.asText() : null;
        }
    }

    static <T> T findValue(JsonNode jsonNode, String fieldName, TypeReference<T> valueTypeReference, ObjectMapper mapper) {
        if (jsonNode == null) {
            return null;
        } else {
            JsonNode value = jsonNode.findValue(fieldName);
            return value != null && value.isContainerNode() ? mapper.convertValue(value, valueTypeReference) : null;
        }
    }

    static JsonNode findObjectNode(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return null;
        } else {
            JsonNode value = jsonNode.findValue(fieldName);
            return value != null && value.isObject() ? value : null;
        }
    }
}
