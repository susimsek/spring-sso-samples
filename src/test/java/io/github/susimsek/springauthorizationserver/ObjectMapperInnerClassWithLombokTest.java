package io.github.susimsek.springauthorizationserver;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.junit.jupiter.api.Test;

class ObjectMapperInnerClassWithLombokTest {

    @Test
    void testInnerObjectWithDateToJson() throws JsonProcessingException {
        // Arrange
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        // İç sınıfın bir örneğini oluştur
        InnerObject innerObject = new InnerObject(new Date());

        // Act
        String jsonResult = objectMapper.writeValueAsString(innerObject);

        // Assert
        assertNotNull(jsonResult);
    }

    // Lombok ile inner sınıf
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    static class InnerObject {
        private Date date;
    }
}
