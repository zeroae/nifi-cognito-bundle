package co.zeroae.nifi.authorization.cognito;

import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.apache.nifi.authorization.*;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GroupType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListGroupsRequest;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class CognitoCaffeineUserGroupProvider extends CognitoNaiveUserGroupProvider {

    // This caches the group names *only*
    // When it expires, we get pull for the groupNames again, and refresh the groupsCache
    LoadingCache<String, Set<GroupType>> groupTypeCache;

    LoadingCache<String, Optional<User>> userByIdentityCache;
    LoadingCache<String, Optional<Group>> groupsCache;

    @Override
    public void initialize(UserGroupProviderInitializationContext initializationContext) throws AuthorizerCreationException {
        super.initialize(initializationContext);
        groupTypeCache = Caffeine.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build(userPoolId -> cognitoClient.listGroupsPaginator(ListGroupsRequest.builder()
                        .userPoolId(userPoolId)
                        .build())
                        .groups()
                        .stream()
                        .collect(Collectors.toSet())
                );
        // TODO: Use a Cache Spec String
        userByIdentityCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(identity ->
                    Optional.ofNullable(CognitoCaffeineUserGroupProvider.super.getUserByIdentity(identity))
                );
        groupsCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(new CacheLoaderAll<String, Group>() {
                    @Override
                    public Optional<Group> load(@NonNull String key) {
                        return Optional.ofNullable(CognitoCaffeineUserGroupProvider.super.getGroup(key));
                    }

                    @Override
                    public Set<Group> getAllValues() {
                        return CognitoCaffeineUserGroupProvider.super.getGroups();
                    }

                    @Override
                    public String getKey(Group value) {
                        return value.getIdentifier();
                    }
                });
    }

    @Override
    public User getUserByIdentity(String identity) throws AuthorizationAccessException {
        return Objects.requireNonNull(userByIdentityCache.get(identity)).orElse(null);
    }

    @Override
    public Set<Group> getGroups() throws AuthorizationAccessException {
        Set<String> groupNames = Objects.requireNonNull(groupTypeCache.get(userPoolId))
                .stream()
                .map(GroupType::groupName)
                .collect(Collectors.toSet());
        groupsCache.getAll(groupNames);// Rewarm the cache

        Set<Group> rv = new HashSet<>();
        groupsCache.asMap().forEach((k, v) -> v.ifPresent(rv::add));
        return Collections.unmodifiableSet(rv);
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        super.onConfigured(configurationContext);
    }

    private abstract static class CacheLoaderAll<K, V> implements CacheLoader<K, Optional<V>> {
        @Override
        public @NonNull Map<@NonNull K, @NonNull Optional<V>> loadAll(@NonNull Iterable<? extends @NonNull K> keys) {
            Map<K, Optional<V>> rv = new HashMap<>();
            Set<V> allValues = getAllValues();
            allValues.forEach(v -> rv.put(getKey(v), Optional.ofNullable(v)));
            keys.forEach(key -> {
                if (!rv.containsKey(key))
                    rv.put(key, Optional.empty());
            });
            return rv;
        }

        public abstract Set<V> getAllValues();
        public abstract K getKey(V value);
    }
}
