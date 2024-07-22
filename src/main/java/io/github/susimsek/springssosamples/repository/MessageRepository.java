package io.github.susimsek.springssosamples.repository;



import io.github.susimsek.springssosamples.entity.MessageEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MessageRepository extends JpaRepository<MessageEntity, Long> {

    List<MessageEntity> findByLocale(String locale);

}
