package io.github.susimsek.springauthorizationserver.security.oauth2.json;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.Requirement;
import java.io.IOException;
import lombok.NoArgsConstructor;

@NoArgsConstructor
public class EncryptionMethodDeserializer extends JsonDeserializer<EncryptionMethod> {

    @Override
    public EncryptionMethod deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);
        return this.deserialize(parser, root);
    }

    private EncryptionMethod deserialize(JsonParser parser, JsonNode root) throws IOException {
        String name = JsonNodeUtils.findStringValue(root, "name");
        if (name == null) {
            throw new JsonParseException(parser, "Missing 'name' field for EncryptionMethod");
        }
        String requirementString = JsonNodeUtils.findStringValue(root, "requirement");
        Requirement requirement = requirementString != null ? Requirement.valueOf(requirementString) : null;
        int cekBitLength = root.has("cekBitLength") ? root.get("cekBitLength").asInt() : 0;

        return new EncryptionMethod(name, requirement, cekBitLength);
    }
}
