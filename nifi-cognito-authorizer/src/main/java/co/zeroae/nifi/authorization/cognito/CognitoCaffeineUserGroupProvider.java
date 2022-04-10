package co.zeroae.nifi.authorization.cognito;

import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.apache.nifi.authorization.*;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GroupType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListGroupsRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class CognitoCaffeineUserGroupProvider extends CognitoNaiveUserGroupProvider {

    // This caches the group names *only*
    // When it expires, we get pull for the groupNames again, and refresh the groupsCache
    LoadingCache<String, Set<GroupType>> groupTypeCache;
    LoadingCache<String, Optional<Group>> groupsCache;

    LoadingCache<String, Set<UserType>> userTypeCache;
    LoadingCache<String, Optional<User>> usersCache;
    LoadingCache<String, Optional<User>> userByIdentityCache;
    LoadingCache<String, UserAndGroups> userAndGroupsCache;

    @Override
    public void initialize(UserGroupProviderInitializationContext initializationContext) throws AuthorizerCreationException {
        super.initialize(initializationContext);
        // TODO: Use a Cache Spec String
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
        groupTypeCache = Caffeine.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build(userPoolId -> cognitoClient.listGroupsPaginator(ListGroupsRequest.builder()
                                .userPoolId(userPoolId)
                                .limit(pageSize)
                                .build())
                        .groups()
                        .stream()
                        .collect(Collectors.toSet())
                );

        userByIdentityCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(identity ->
                        Optional.ofNullable(CognitoCaffeineUserGroupProvider.super.getUserByIdentity(identity))
                );
        userAndGroupsCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(CognitoCaffeineUserGroupProvider.super::getUserAndGroups);
        usersCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(new CacheLoaderAll<String, User>() {
                    @Override
                    public Optional<User> load(@NonNull String key) {
                        return Optional.ofNullable(CognitoCaffeineUserGroupProvider.super.getUser(key));
                    }

                    @Override
                    public Set<User> getAllValues() {return CognitoCaffeineUserGroupProvider.super.getUsers();}

                    @Override
                    public String getKey(User value) {return value.getIdentifier();}
                });
        userTypeCache = Caffeine.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build(userPoolId -> cognitoClient.listUsersPaginator(ListUsersRequest.builder()
                                .userPoolId(userPoolId)
                                .limit(pageSize)
                                .build())
                        .users()
                        .stream()
                        .collect(Collectors.toSet())
                );
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
    public Group getGroup(String identifier) throws AuthorizationAccessException {
        return Objects.requireNonNull(groupsCache.get(identifier)).orElse(null);
    }

    @Override
    public Set<User> getUsers() throws AuthorizationAccessException {
        Set<String> userNames = Objects.requireNonNull(userTypeCache.get(userPoolId))
                .stream()
                .map(UserType::username)
                .collect(Collectors.toSet());
        usersCache.getAll(userNames);
        Set<User> rv = new HashSet<>();
        usersCache.asMap().forEach((k,v ) -> v.ifPresent(rv::add));
        return Collections.unmodifiableSet(rv);
    }

    @Override
    public User getUser(String identifier) throws AuthorizationAccessException {
        return Objects.requireNonNull(usersCache.get(identifier)).orElse(null);
    }

    @Override
    public UserAndGroups getUserAndGroups(String identity) throws AuthorizationAccessException {
        return userAndGroupsCache.get(identity);
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
