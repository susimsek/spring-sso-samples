package io.github.susimsek.springauthorizationserver.security.session;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.core.serializer.Deserializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.core.serializer.support.DeserializingConverter;
import org.springframework.core.serializer.support.SerializingConverter;
import org.springframework.lang.NonNull;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JsonConversionUtils {

    private final GenericConversionService conversionService;

    public JsonConversionUtils() {
        ObjectMapper objectMapper = new ObjectMapper();
        ClassLoader classLoader = getClass().getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        GenericConversionService converter = new GenericConversionService();
        converter.addConverter(Object.class, byte[].class, new SerializingConverter(new JsonSerializer(objectMapper)));
        converter.addConverter(byte[].class, Object.class,
            new DeserializingConverter(new JsonDeserializer(objectMapper)));
        this.conversionService = converter;
    }

    public byte[] serialize(Object object) {
        return (byte[]) this.conversionService.convert(object, TypeDescriptor.valueOf(Object.class),
            TypeDescriptor.valueOf(byte[].class));
    }

    public Object deserialize(byte[] bytes) {
        return this.conversionService.convert(bytes, TypeDescriptor.valueOf(byte[].class),
            TypeDescriptor.valueOf(Object.class));
    }

    static class JsonSerializer implements Serializer<Object> {

        private final ObjectMapper objectMapper;

        JsonSerializer(ObjectMapper objectMapper) {
            this.objectMapper = objectMapper;
        }

        @Override
        public void serialize(@NonNull Object object,
                              @NonNull OutputStream outputStream) throws IOException {
            this.objectMapper.writeValue(outputStream, object);
        }

    }

    static class JsonDeserializer implements Deserializer<Object> {

        private final ObjectMapper objectMapper;

        JsonDeserializer(ObjectMapper objectMapper) {
            this.objectMapper = objectMapper;
        }

        @Override
        @NonNull
        public Object deserialize(@NonNull InputStream inputStream) throws IOException {
            return this.objectMapper.readValue(inputStream, Object.class);
        }

    }
}
