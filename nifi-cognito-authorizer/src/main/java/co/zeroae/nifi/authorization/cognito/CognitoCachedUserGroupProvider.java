package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.*;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.AuthorizerDestructionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListGroupsIterable;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListUsersInGroupIterable;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The CognitoUserGroupProvider provides support for retrieving users and
 * groups from AWS Cognito using the AWS SDK.
 *
 * ref: https://github.com/awsdocs/aws-doc-sdk-examples/tree/main/javav2/example_code/cognito
 * ref: AzureGraphUserGroupProvider
 */
public class CognitoCachedUserGroupProvider extends AbstractCognitoUserGroupProvider implements UserGroupProvider {
    private final static Logger logger = LoggerFactory.getLogger(CognitoCachedUserGroupProvider.class);

    public static final String REFRESH_DELAY_PROPERTY = "Refresh Delay";
    public static final String DEFAULT_REFRESH_DELAY = "5 mins";

    private ScheduledExecutorService scheduler;

    private final AtomicReference<ImmutableCognitoUserGroup> cognitoUserGroupRef = new AtomicReference<>();

    @Override
    public Set<User> getUsers() throws AuthorizationAccessException {
        return cognitoUserGroupRef.get().getUsers();
    }

    @Override
    public User getUser(String identifier) throws AuthorizationAccessException {
        return cognitoUserGroupRef.get().getUser(identifier);
    }

    @Override
    public User getUserByIdentity(String identity) throws AuthorizationAccessException {
        return cognitoUserGroupRef.get().getUserByPrincipalName(identity);
    }

    @Override
    public Set<Group> getGroups() throws AuthorizationAccessException {
        return cognitoUserGroupRef.get().getGroups();
    }

    @Override
    public Group getGroup(String identifier) throws AuthorizationAccessException {
        return cognitoUserGroupRef.get().getGroup(identifier);
    }

    @Override
    public Group getGroupByName(String name) throws AuthorizationAccessException {
        return cognitoUserGroupRef.get().getGroupByDisplayName(name);
    }

    @Override
    public UserAndGroups getUserAndGroups(String identity) throws AuthorizationAccessException {
        return cognitoUserGroupRef.get().getUserAndGroups(identity);
    }

    @Override
    public void initialize(UserGroupProviderInitializationContext initializationContext) throws AuthorizerCreationException {
        this.scheduler = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                final Thread thread = Executors.defaultThreadFactory().newThread(r);
                thread.setName(String.format("%s (%s) - UserGroup Refresh", getClass().getSimpleName(), initializationContext.getIdentifier()));
                return thread;
            }
        });
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        super.onConfigured(configurationContext);
        final long fixedDelay = getDelayProperty(configurationContext, REFRESH_DELAY_PROPERTY, DEFAULT_REFRESH_DELAY);

        try {
            refreshUserGroup(userPoolId);
        } catch (final CognitoIdentityProviderException e) {
            throw new AuthorizerCreationException(String.format("Failed to load UserGroup due to %s", e.getMessage()), e);
        }
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                refreshUserGroup(userPoolId);
            } catch (final Throwable t) {
                logger.error("Error refreshing user groups due to {}", t.getMessage(), t);
            }
        }, fixedDelay, fixedDelay, TimeUnit.MILLISECONDS);
    }

    protected void refreshUserGroup(String userPoolId) {
        final Set<GroupType> groupNames = getGroupsWith(userPoolId, pageSize);
        refreshUserGroupData(userPoolId, groupNames, pageSize);
    }

    private void refreshUserGroupData(String userPoolId, Set<GroupType> groups, int pageSize) {
        Objects.requireNonNull(groups);

        final Set<User> rv_users = new HashSet<>();
        final Set<Group> rv_groups= new HashSet<>();

        for (GroupType group: groups) {
            if (logger.isDebugEnabled()) logger.debug("Getting users for group: {}", group.groupName());
            UserGroupQueryResult queryResult = getUsersFrom(userPoolId, group, pageSize);
            rv_groups.add(queryResult.getGroup());
            rv_users.addAll(queryResult.getUsers());
        }
        final ImmutableCognitoUserGroup cognitoUserGroup = ImmutableCognitoUserGroup.newInstance(rv_users, rv_groups);
        cognitoUserGroupRef.set(cognitoUserGroup);
    }

    private UserGroupQueryResult getUsersFrom(String userPoolId, GroupType group, int pageSize) {
        Set<UserType> rv = new HashSet<>();
        ListUsersInGroupRequest request = ListUsersInGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(group.groupName())
                .limit(pageSize)
                .build();
        ListUsersInGroupIterable responses = cognitoClient.listUsersInGroupPaginator(request);
        responses.stream().forEach(response -> rv.addAll(response.users()));
        return new UserGroupQueryResult(group, Collections.unmodifiableSet(rv));
    }

    private Set<GroupType> getGroupsWith(String userPoolId, int pageSize) {
        Set<GroupType> rv = new HashSet<>();
        ListGroupsRequest groupsRequest = ListGroupsRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .build();
        ListGroupsIterable responses = cognitoClient.listGroupsPaginator(groupsRequest);
        responses.forEach(response -> rv.addAll(response.groups()));
        return Collections.unmodifiableSet(rv);
    }

    @Override
    public void preDestruction() throws AuthorizerDestructionException {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(10000, TimeUnit.MILLISECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (final InterruptedException e) {
            logger.warn("Error shutting down user group refresh scheduler due to {}", e.getMessage(), e);
        } finally {
            super.preDestruction();
        }
    }

    private static class UserGroupQueryResult {
        private final Group group;
        private final Set<User> users;

        public UserGroupQueryResult(GroupType group, Set<UserType> users) {
            Group.Builder gBuilder = new Group.Builder().name(group.description()).identifier(group.groupName());
            this.users = new HashSet<>();
            for (UserType user : users) {
                User.Builder uBuilder = new User.Builder().identifier(user.username());
                gBuilder.addUser(user.username());
                user.attributes().forEach(attributeType -> {
                    if (attributeType.name().equals(IDENTITY_ATTRIBUTE))
                        uBuilder.identity(attributeType.value());
                });
                this.users.add(uBuilder.build());
            }
            this.group = gBuilder.build();
        }

        public Group getGroup() {
            return this.group;
        }

        public Set<User> getUsers() {
            return this.users;
        }
    }

}
