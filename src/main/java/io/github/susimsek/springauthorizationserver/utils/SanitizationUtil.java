package io.github.susimsek.springauthorizationserver.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.regex.Pattern;
import lombok.experimental.UtilityClass;

@UtilityClass
public class SanitizationUtil {

    private static final Pattern[] patterns = new Pattern[] {
        Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("src[\r\n]*=[\r\n]*'(.*?)'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        Pattern.compile("src[\r\n]*=[\r\n]*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        Pattern.compile("</script>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL)
    };

    private final ObjectMapper objectMapper = new ObjectMapper();

    public static String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }

        String sanitized = input;
        for (Pattern pattern : patterns) {
            sanitized = pattern.matcher(sanitized).replaceAll("");
        }

        return sanitized;
    }

    public JsonNode sanitizeJsonNode(JsonNode jsonNode) {
        if (jsonNode.isObject()) {
            jsonNode.fields().forEachRemaining(entry -> {
                JsonNode value = entry.getValue();
                if (value.isTextual()) {
                    ((ObjectNode) jsonNode).put(entry.getKey(), sanitizeInput(value.textValue()));
                } else if (value.isContainerNode()) {
                    sanitizeJsonNode(value);
                }
            });
        } else if (jsonNode.isArray()) {
            jsonNode.forEach(SanitizationUtil::sanitizeJsonNode);
        }
        return jsonNode;
    }

    public String sanitizeJsonString(String jsonString) {
        try {
            JsonNode jsonNode = objectMapper.readTree(jsonString);
            jsonNode = sanitizeJsonNode(jsonNode);
            return objectMapper.writeValueAsString(jsonNode);
        } catch (IOException e) {
            return jsonString;
        }
    }

    public byte[] sanitizeJson(byte[] jsonContent) {
        try {
            JsonNode jsonNode = objectMapper.readTree(jsonContent);
            jsonNode = sanitizeJsonNode(jsonNode);
            return objectMapper.writeValueAsBytes(jsonNode);
        } catch (IOException e) {
            return jsonContent;
        }
    }
}
