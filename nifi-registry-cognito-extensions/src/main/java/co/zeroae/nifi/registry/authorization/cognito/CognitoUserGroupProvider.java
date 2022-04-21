package co.zeroae.nifi.registry.authorization.cognito;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.apache.nifi.registry.security.authorization.*;
import org.apache.nifi.registry.security.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.registry.security.exception.SecurityProviderCreationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GroupType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListGroupsRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CognitoUserGroupProvider extends CognitoNaiveUserGroupProvider {

    // groupTypeCache is looking for names only
    // When it expires, we refresh the groupsCache
    LoadingCache<String, Set<GroupType>> groupTypeCache;
    LoadingCache<String, Optional<Group>> groupsCache;

    // userTypeCache is looking for names only
    // When it expires, we pull the usersCache, byIdentty and userAndGroups
    LoadingCache<String, Set<UserType>> userTypeCache;
    LoadingCache<String, Optional<User>> usersCache;
    LoadingCache<String, Optional<User>> userByIdentityCache;
    LoadingCache<String, UserAndGroups> userAndGroupsCache;

    @Override
    public void initialize(UserGroupProviderInitializationContext initializationContext) throws SecurityProviderCreationException {
        super.initialize(initializationContext);
        // TODO: Use a Cache Spec String
        groupsCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(new AbstractCacheLoaderAll<String, Group>() {
                    @Override
                    public Optional<Group> load(@NonNull String key) {
                        return Optional.ofNullable(CognitoUserGroupProvider.super.getGroup(key));
                    }

                    @Override
                    public Set<Group> getAllValues() {
                        return CognitoUserGroupProvider.super.getGroups();
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
                        .filter(group -> !group.groupName().startsWith(AbstractCognitoUserGroupProvider.EXCLUDE_GROUP_PREFIX))
                        .collect(Collectors.toSet())
                );

        userByIdentityCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(identity ->
                        Optional.ofNullable(CognitoUserGroupProvider.super.getUserByIdentity(identity))
                );
        userAndGroupsCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(CognitoUserGroupProvider.super::getUserAndGroups);
        usersCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(new AbstractCacheLoaderAll<String, User>() {
                    @Override
                    public Optional<User> load(@NonNull String key) {
                        return Optional.ofNullable(CognitoUserGroupProvider.super.getUser(key));
                    }

                    @Override
                    public Set<User> getAllValues() {return CognitoUserGroupProvider.super.getUsers();}

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
                        .filter(user -> !user.username().startsWith(AbstractCognitoUserGroupProvider.GROUP_PROXY_USER_PREFIX))
                        .collect(Collectors.toSet())
                );
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws SecurityProviderCreationException{
        super.onConfigured(configurationContext);
        Stream.of(
                groupTypeCache, groupsCache,
                userTypeCache, usersCache, userByIdentityCache, userAndGroupsCache
        ).forEachOrdered(Cache::invalidateAll);
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
    public Group addGroup(Group group) throws AuthorizationAccessException {
        final Group rv = super.addGroup(group);
        groupsCache.invalidate(group.getIdentifier());
        return rv;
    }

    @Override
    public Group updateGroup(Group group) throws AuthorizationAccessException {
        // Invalidate before updating to ensure we have the latest version in the cache.
        groupsCache.invalidate(group.getIdentifier());
        return super.updateGroup(group);
    }

    @Override
    public Group deleteGroup(Group group) throws AuthorizationAccessException {
        try {
            return super.deleteGroup(group);
        } finally {
            groupsCache.invalidate(group.getIdentifier());
        }
    }

    @Override
    protected void addUserToGroup(String userIdentifier, String groupIdentifier) {
        super.addUserToGroup(userIdentifier, groupIdentifier);
        groupsCache.invalidate(groupIdentifier);
        userAndGroupsCache.invalidate(getUser(userIdentifier).getIdentity());
    }

    @Override
    protected void removeUserFromGroup(String userIdentifier, String groupIdentifier) {
        try {
            super.removeUserFromGroup(userIdentifier, groupIdentifier);
        } finally {
            groupsCache.invalidate(groupIdentifier);
            userAndGroupsCache.invalidate(getUser(userIdentifier).getIdentity());
        }
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
    public User addUser(User user) throws AuthorizationAccessException {
        final User rv = super.addUser(user);
        usersCache.invalidate(user.getIdentifier());
        userByIdentityCache.invalidate(user.getIdentity());
        userAndGroupsCache.invalidate(user.getIdentity());
        return rv;
    }

    @Override
    public User deleteUser(User user) throws AuthorizationAccessException {
        Set<Group> userGroups = getUserAndGroups(user.getIdentity()).getGroups();
        try {
            return super.deleteUser(user);
        } finally {
            usersCache.invalidate(user.getIdentifier());
            userByIdentityCache.invalidate(user.getIdentity());
            userAndGroupsCache.invalidate(user.getIdentity());
            groupsCache.invalidateAll(userGroups.stream().map(Group::getIdentifier).collect(Collectors.toSet()));
        }
    }

    @Override
    public UserAndGroups getUserAndGroups(String identity) throws AuthorizationAccessException {
        return userAndGroupsCache.get(identity);
    }


}
