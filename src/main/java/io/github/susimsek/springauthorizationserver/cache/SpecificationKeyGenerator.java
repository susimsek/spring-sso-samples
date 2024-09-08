package io.github.susimsek.springauthorizationserver.cache;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.DigestUtils;

@Component("specificationKeyGenerator")
public class SpecificationKeyGenerator implements KeyGenerator {

    @Override
    @NonNull
    public Object generate(Object target, Method method, Object... params) {
        StringBuilder keyBuilder = new StringBuilder();

        keyBuilder.append(target.getClass().getSimpleName()).append(".");
        keyBuilder.append(method.getName()).append(":");

        for (Object param : params) {
            if (param instanceof Specification<?> specification) {
                keyBuilder.append(hashSpecification(specification));
            } else {
                keyBuilder.append(param.hashCode()).append(",");
            }
        }

        return keyBuilder.toString();
    }

    private String hashSpecification(Specification<?> specification) {
        return DigestUtils.md5DigestAsHex(specification.toString().getBytes(StandardCharsets.UTF_8));
    }
}
