package io.github.susimsek.springauthorizationserver.service;

import io.github.susimsek.springauthorizationserver.entity.UserSessionAttributeEntity;
import io.github.susimsek.springauthorizationserver.entity.UserSessionAttributeId;
import io.github.susimsek.springauthorizationserver.entity.UserSessionEntity;
import io.github.susimsek.springauthorizationserver.repository.UserSessionAttributeRepository;
import io.github.susimsek.springauthorizationserver.repository.UserSessionRepository;
import io.github.susimsek.springauthorizationserver.security.session.JsonConversionUtils;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.session.DelegatingIndexResolver;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.IndexResolver;
import org.springframework.session.MapSession;
import org.springframework.session.PrincipalNameIndexResolver;
import org.springframework.session.SaveMode;
import org.springframework.session.Session;
import org.springframework.session.SessionIdGenerator;
import org.springframework.session.UuidSessionIdGenerator;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

@RequiredArgsConstructor
public class DomainSessionService
    implements FindByIndexNameSessionRepository<DomainSessionService.UserSession>, InitializingBean, DisposableBean {

    private final UserSessionRepository springSessionRepository;

    private final UserSessionAttributeRepository springSessionAttributeRepository;

    private final JsonConversionUtils jsonConversionUtils;

    private Duration defaultMaxInactiveInterval = Duration.ofSeconds(1800L);

    @Setter
    private IndexResolver<Session> indexResolver = new DelegatingIndexResolver<>(new PrincipalNameIndexResolver<>());
    private SessionIdGenerator sessionIdGenerator = UuidSessionIdGenerator.getInstance();
    private String cleanupCron = "0 * * * * *";
    private ThreadPoolTaskScheduler taskScheduler;

    @Setter
    private SaveMode saveMode = SaveMode.ON_SET_ATTRIBUTE;

    public void setDefaultMaxInactiveInterval(Duration defaultMaxInactiveInterval) {
        Assert.notNull(defaultMaxInactiveInterval, "defaultMaxInactiveInterval must not be null");
        this.defaultMaxInactiveInterval = defaultMaxInactiveInterval;
    }

    public void setSessionIdGenerator(SessionIdGenerator sessionIdGenerator) {
        Assert.notNull(sessionIdGenerator, "sessionIdGenerator cannot be null");
        this.sessionIdGenerator = sessionIdGenerator;
    }

    @Override
    public void afterPropertiesSet() {
        if (!"-".equals(this.cleanupCron)) {
            this.taskScheduler = createTaskScheduler();
            this.taskScheduler.initialize();
            this.taskScheduler.schedule(this::cleanUpExpiredSessions, new CronTrigger(this.cleanupCron));
        }
    }

    @Override
    public void destroy() {
        if (this.taskScheduler != null) {
            this.taskScheduler.destroy();
        }
    }

    private static ThreadPoolTaskScheduler createTaskScheduler() {
        ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
        taskScheduler.setThreadNamePrefix("spring-session-");
        return taskScheduler;
    }

    public void setCleanupCron(String cleanupCron) {
        Assert.notNull(cleanupCron, "cleanupCron must not be null");
        if (!"-".equals(cleanupCron)) {
            Assert.isTrue(CronExpression.isValidExpression(cleanupCron), "cleanupCron must be valid");
        }

        this.cleanupCron = cleanupCron;
    }

    public UserSession createSession() {
        MapSession delegate = new MapSession(sessionIdGenerator.generate());
        delegate.setMaxInactiveInterval(defaultMaxInactiveInterval);
        return new UserSession(delegate, UUID.randomUUID().toString(), true);
    }

    @Override
    @Transactional
    public void save(UserSession session) {
        session.save();
    }

    public UserSession findById(String id) {
        Optional<UserSessionEntity> optionalSessionEntity = springSessionRepository.findBySessionId(id);

        if (optionalSessionEntity.isPresent()) {
            UserSessionEntity sessionEntity = optionalSessionEntity.get();
            UserSession session = convertToJdbcSession(sessionEntity);
            if (!session.isExpired()) {
                return session;
            }
            this.deleteById(id);
        }

        return null;
    }

    public void deleteById(String id) {
        springSessionRepository.deleteBySessionId(id);
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, UserSession> findByIndexNameAndIndexValue(String indexName, final String indexValue) {
        if (!PRINCIPAL_NAME_INDEX_NAME.equals(indexName)) {
            return Collections.emptyMap();
        } else {
            List<UserSession> sessions = springSessionRepository.findByPrincipalName(indexValue)
                .stream()
                .map(this::convertToJdbcSession)
                .toList();

            Map<String, UserSession> sessionMap = new HashMap<>(sessions.size());
            for (UserSession session : sessions) {
                sessionMap.put(session.getId(), session);
            }

            return sessionMap;
        }
    }


    private UserSession convertToJdbcSession(UserSessionEntity sessionEntity) {
        MapSession delegate = new MapSession(sessionEntity.getSessionId());
        delegate.setCreationTime(sessionEntity.getCreationTime());
        delegate.setLastAccessedTime(sessionEntity.getLastAccessTime());
        delegate.setMaxInactiveInterval(Duration.ofSeconds(sessionEntity.getMaxInactiveInterval()));

        UserSession session = new UserSession(delegate, sessionEntity.getId(), false);

        for (UserSessionAttributeEntity attribute : sessionEntity.getAttributes()) {
            byte[] bytes = attribute.getAttributeBytes();
            String attributeName = attribute.getAttributeName();
            session.delegate.setAttribute(attributeName, DomainSessionService.lazily(
                () -> jsonConversionUtils.deserialize(bytes)));
        }

        return session;
    }


    public void cleanUpExpiredSessions() {
        springSessionRepository.deleteByExpiryTimeBefore(Instant.now());
    }

    private static <T> Supplier<T> value(T value) {
        return value != null ? () -> value : null;
    }

    public static <T> Supplier<T> lazily(final Supplier<T> supplier) {
        Supplier<T> lazySupplier = new Supplier<>() {
            private T value;

            public T get() {
                if (this.value == null) {
                    this.value = supplier.get();
                }

                return this.value;
            }
        };
        return supplier != null ? lazySupplier : null;
    }

    public class UserSession implements Session {
        public final MapSession delegate;
        private final String id;
        private boolean isNew;
        private boolean changed;
        private final Map<String, DeltaValue> delta = new HashMap<>();

        public UserSession(MapSession delegate, String id, boolean isNew) {
            this.delegate = delegate;
            this.id = id;
            this.isNew = isNew;
            if (this.isNew || DomainSessionService.this.saveMode == SaveMode.ALWAYS) {
                this.getAttributeNames().forEach(attributeName -> this.delta.put(attributeName, DeltaValue.UPDATED));
            }
        }

        boolean isNew() {
            return this.isNew;
        }

        boolean isChanged() {
            return this.changed;
        }

        Map<String, DeltaValue> getDelta() {
            return this.delta;
        }

        void clearChangeFlags() {
            this.isNew = false;
            this.changed = false;
            this.delta.clear();
        }

        Instant getExpiryTime() {
            return this.getMaxInactiveInterval().isNegative() ? Instant.ofEpochMilli(Long.MAX_VALUE) : this.getLastAccessedTime().plus(this.getMaxInactiveInterval());
        }

        public String getId() {
            return this.delegate.getId();
        }

        public String changeSessionId() {
            this.changed = true;
            String newSessionId = DomainSessionService.this.sessionIdGenerator.generate();
            this.delegate.setId(newSessionId);
            return newSessionId;
        }

        public <T> T getAttribute(String attributeName) {
            Supplier<T> supplier = this.delegate.getAttribute(attributeName);
            if (supplier == null) {
                return null;
            } else {
                T attributeValue = supplier.get();
                if (attributeValue != null && DomainSessionService.this.saveMode.equals(SaveMode.ON_GET_ATTRIBUTE)) {
                    this.delta.merge(attributeName, DomainSessionService.DeltaValue.UPDATED, (oldDeltaValue, deltaValue) ->
                        oldDeltaValue == DeltaValue.ADDED ? oldDeltaValue : deltaValue);
                }

                return attributeValue;
            }
        }

        @Override
        public Set<String> getAttributeNames() {
            return delegate.getAttributeNames();
        }

        public void setAttribute(String attributeName, Object attributeValue) {
            boolean attributeExists = this.delegate.getAttribute(attributeName) != null;
            boolean attributeRemoved = attributeValue == null;

            if (!shouldProcessAttribute(attributeExists, attributeRemoved)) {
                return;
            }

            updateDelta(attributeName, attributeExists, attributeRemoved);
            this.delegate.setAttribute(attributeName, DomainSessionService.value(attributeValue));
            updateChangedFlag(attributeName);
        }

        private boolean shouldProcessAttribute(boolean attributeExists, boolean attributeRemoved) {
            return attributeExists || !attributeRemoved;
        }

        private void updateDelta(String attributeName, boolean attributeExists, boolean attributeRemoved) {
            if (attributeExists) {
                handleExistingAttribute(attributeName, attributeRemoved);
            } else {
                this.delta.merge(attributeName, DomainSessionService.DeltaValue.ADDED, this::determineDeltaValueForNewAttribute);
            }
        }

        private void handleExistingAttribute(String attributeName, boolean attributeRemoved) {
            if (attributeRemoved) {
                this.delta.merge(attributeName, DomainSessionService.DeltaValue.REMOVED, this::determineDeltaValueForRemovedAttribute);
            } else {
                this.delta.merge(attributeName, DomainSessionService.DeltaValue.UPDATED, this::determineDeltaValueForUpdatedAttribute);
            }
        }

        private DeltaValue determineDeltaValueForNewAttribute(DeltaValue oldDeltaValue, DeltaValue deltaValue) {
            return oldDeltaValue == DeltaValue.ADDED ? oldDeltaValue : DeltaValue.UPDATED;
        }

        private DeltaValue determineDeltaValueForRemovedAttribute(DeltaValue oldDeltaValue, DeltaValue deltaValue) {
            return oldDeltaValue == DeltaValue.ADDED ? null : deltaValue;
        }

        private DeltaValue determineDeltaValueForUpdatedAttribute(DeltaValue oldDeltaValue, DeltaValue deltaValue) {
            return oldDeltaValue == DeltaValue.ADDED ? oldDeltaValue : deltaValue;
        }

        private void updateChangedFlag(String attributeName) {
            if (FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME.equals(attributeName) || "SPRING_SECURITY_CONTEXT".equals(attributeName)) {
                this.changed = true;
            }
        }

        @Override
        public void removeAttribute(String attributeName) {
            setAttribute(attributeName, null);
        }

        @Override
        public Instant getCreationTime() {
            return delegate.getCreationTime();
        }

        public void setLastAccessedTime(Instant lastAccessedTime) {
            this.delegate.setLastAccessedTime(lastAccessedTime);
            this.changed = true;
        }

        public Instant getLastAccessedTime() {
            return this.delegate.getLastAccessedTime();
        }

        public void setMaxInactiveInterval(Duration interval) {
            this.delegate.setMaxInactiveInterval(interval);
            this.changed = true;
        }

        @Override
        public Duration getMaxInactiveInterval() {
            return this.delegate.getMaxInactiveInterval();
        }


        public boolean isExpired() {
            return this.delegate.isExpired();
        }

        private void save() {
            if (this.isNew) {
                saveNewSession();
            } else {
                updateExistingSession();
            }
            this.clearChangeFlags();
        }

        private void saveNewSession() {
            Map<String, String> indexes = indexResolver.resolveIndexesFor(this);
            UserSessionEntity sessionEntity = new UserSessionEntity();
            sessionEntity.setId(this.id);
            sessionEntity.setSessionId(this.getId());
            sessionEntity.setCreationTime(this.getCreationTime());
            sessionEntity.setLastAccessTime(this.getLastAccessedTime());
            sessionEntity.setMaxInactiveInterval((int) this.getMaxInactiveInterval().getSeconds());
            sessionEntity.setExpiryTime(this.getExpiryTime());
            sessionEntity.setPrincipalName(indexes.get(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME));

            springSessionRepository.save(sessionEntity);
            Set<String> attributeNames = this.getAttributeNames();
            if (!attributeNames.isEmpty()) {
                insertSessionAttributes(this, attributeNames, sessionEntity);
            }
        }

        private void updateExistingSession() {
            Map<String, String> indexes = indexResolver.resolveIndexesFor(this);
            Optional<UserSessionEntity> optionalSpringSessionEntity = springSessionRepository.findById(this.id);
            if (optionalSpringSessionEntity.isPresent()) {
                UserSessionEntity sessionEntity = optionalSpringSessionEntity.get();
                sessionEntity.setSessionId(this.getId());
                sessionEntity.setLastAccessTime(this.getLastAccessedTime());
                sessionEntity.setMaxInactiveInterval((int) this.getMaxInactiveInterval().getSeconds());
                sessionEntity.setExpiryTime(this.getExpiryTime());
                sessionEntity.setPrincipalName(indexes.get(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME));

                springSessionRepository.save(sessionEntity);

                Set<String> addedAttributeNames = delta.entrySet().stream()
                    .filter(entry -> entry.getValue() == DeltaValue.ADDED)
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toSet());
                if (!addedAttributeNames.isEmpty()) {
                    insertSessionAttributes(this, addedAttributeNames, sessionEntity);
                }

                List<String> updatedAttributeNames = delta.entrySet().stream()
                    .filter(entry -> entry.getValue() == DeltaValue.UPDATED)
                    .map(Map.Entry::getKey)
                    .toList();
                if (!updatedAttributeNames.isEmpty()) {
                    updateSessionAttributes(this, updatedAttributeNames);
                }

                List<String> removedAttributeNames = delta.entrySet().stream()
                    .filter(entry -> entry.getValue() == DeltaValue.REMOVED)
                    .map(Map.Entry::getKey)
                    .toList();
                if (!removedAttributeNames.isEmpty()) {
                    deleteSessionAttributes(this, removedAttributeNames);
                }
            }
        }

        private void insertSessionAttributes(final UserSession session,
                                             Set<String> attributeNames, UserSessionEntity sessionEntity) {
            var attributeEntities = attributeNames.stream().map(attributeName -> {
                UserSessionAttributeEntity attributeEntity = new UserSessionAttributeEntity();
                attributeEntity.setSessionId(session.id);
                attributeEntity.setAttributeName(attributeName);
                attributeEntity.setAttributeBytes(jsonConversionUtils.serialize(session.getAttribute(attributeName)));
                attributeEntity.setSession(sessionEntity);
                return attributeEntity;
            }).collect(Collectors.toSet());
            sessionEntity.getAttributes().addAll(attributeEntities);
            springSessionRepository.save(sessionEntity);
        }

        private void updateSessionAttributes(UserSession session,
                                             List<String> attributeNames) {
            attributeNames.forEach(attributeName -> springSessionAttributeRepository.findById(
                new UserSessionAttributeId(session.id, attributeName))
                .ifPresent(attributeEntity -> {
                    attributeEntity.setAttributeBytes(jsonConversionUtils.serialize(session.getAttribute(attributeName)));
                    springSessionAttributeRepository.save(attributeEntity);
                }));
        }

        private void deleteSessionAttributes(UserSession session,
                                             List<String> attributeNames) {
            attributeNames.forEach(attributeName ->
                springSessionAttributeRepository.deleteById(new UserSessionAttributeId(session.id,
                attributeName)));
        }
    }

    private enum DeltaValue {
        ADDED,
        UPDATED,
        REMOVED;
        DeltaValue() {
        }
    }
}
