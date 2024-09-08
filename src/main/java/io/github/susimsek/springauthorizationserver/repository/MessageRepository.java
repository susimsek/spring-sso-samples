package io.github.susimsek.springauthorizationserver.repository;


import io.github.susimsek.springauthorizationserver.entity.MessageEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MessageRepository extends JpaRepository<MessageEntity, Long> {

    List<MessageEntity> findByLocale(String locale);

}
