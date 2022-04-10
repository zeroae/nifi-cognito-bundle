package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.Group;
import org.apache.nifi.authorization.User;
import org.apache.nifi.authorization.UserAndGroups;
import org.apache.nifi.authorization.UserGroupProviderInitializationContext;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.util.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class CognitoNaiveUserGroupProvider extends AbstractCognitoUserGroupProvider {
    private final static Logger logger = LoggerFactory.getLogger(CognitoNaiveUserGroupProvider.class);

    @Override
    public void initialize(UserGroupProviderInitializationContext initializationContext) throws AuthorizerCreationException {
    }

    @Override
    public Set<User> getUsers() throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        final Set<User> rv = new HashSet<>();
        final ListUsersRequest request = ListUsersRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .attributesToGet(IDENTITY_ATTRIBUTE)
                .build();
        watch.start();
        try {
            cognitoClient.listUsersPaginator(request).users().forEach(user -> {
                final User.Builder userBuilder = new User.Builder()
                        .identifier(user.username());
                user.attributes().forEach(attribute -> {
                    if (attribute.name().equals(IDENTITY_ATTRIBUTE))
                        userBuilder.identity(attribute.value());
                });
                rv.add(userBuilder.build());
            });
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getUsers: " + watch.getDuration());
        }
        return Collections.unmodifiableSet(rv);
    }

    @Override
    public User getUser(String identifier) throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        AdminGetUserRequest request = AdminGetUserRequest.builder()
                .userPoolId(userPoolId)
                .username(identifier)
                .build();
        watch.start();
        try {
            AdminGetUserResponse response = cognitoClient.adminGetUser(request);
            final User.Builder userBuilder = new User.Builder().identifier(response.username());
            response.userAttributes().forEach(attribute -> {
                if (attribute.name().equals(IDENTITY_ATTRIBUTE))
                    userBuilder.identity(attribute.name());
            });
            return userBuilder.build();
        } catch (ResourceNotFoundException e) {
            return null;
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException("Error getting user: " + identifier, e);
        } finally {
            watch.stop();
            logger.debug("getUser elapsed: " + watch.getDuration());
        }
    }

    @Override
    public User getUserByIdentity(String identity) throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        final ListUsersRequest request = ListUsersRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .attributesToGet(IDENTITY_ATTRIBUTE)
                .filter(String.format("email = \"%s\"", identity))
                .build();
        watch.start();
        try {
            for (UserType user : cognitoClient.listUsersPaginator(request).users()) {
                User.Builder userBuilder = new User.Builder().identifier(user.username());
                user.attributes().forEach(attribute -> {
                    if (attribute.name().equals(IDENTITY_ATTRIBUTE))
                        userBuilder.identity(attribute.value());
                });
                return userBuilder.build();
            }
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getUserByIdentity: " + watch.getDuration());
        }
        return null;
    }

    @Override
    public Set<Group> getGroups() throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        final Set<Group> rv = new HashSet<>();
        final ListGroupsRequest listGroupsRequest = ListGroupsRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .build();
        watch.start();
        try {
            cognitoClient.listGroupsPaginator(listGroupsRequest).groups().forEach(group -> {
                final Group.Builder groupBuilder = new Group.Builder()
                        .identifier(group.groupName())
                        .name(group.description());
                getUsersInGroup(group.groupName()).forEach(groupBuilder::addUser);
                rv.add(groupBuilder.build());
            });
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getGroups: " + watch.getDuration());
        }
        return Collections.unmodifiableSet(rv);
    }

    @Override
    public Group getGroup(String identifier) throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        GetGroupRequest request =GetGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(identifier)
                .build();
        watch.start();
        try {
            GroupType group = cognitoClient.getGroup(request).group();
            Group.Builder groupBuilder = new Group.Builder()
                    .identifier(group.groupName())
                    .name(group.description());
            getUsersInGroup(identifier).forEach(groupBuilder::addUser);
            return groupBuilder.build();
        } catch (ResourceNotFoundException e) {
            return null;
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getGroup: " + watch.getDuration());
        }
    }

    protected Set<String> getUsersInGroup(String identifier) throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        final ListUsersInGroupRequest listUsersInGroupRequest = ListUsersInGroupRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .groupName(identifier)
                .build();
        watch.start();
        try {
            return cognitoClient.listUsersInGroupPaginator(listUsersInGroupRequest)
                    .users()
                    .stream()
                    .map(UserType::username)
                    .collect(Collectors.toSet());
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getUsersInGroup: " + watch.getDuration());
        }
    }

    @Override
    public UserAndGroups getUserAndGroups(String identity) throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        watch.start();

        final User user = getUserByIdentity(identity);
        if (user == null)
            return UserAndGroups.EMPTY;

        AdminListGroupsForUserRequest request = AdminListGroupsForUserRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .username(user.getIdentifier())
                .build();
        try {
            final Set<Group> groups = Collections.unmodifiableSet(cognitoClient.adminListGroupsForUserPaginator(request)
                    .groups()
                    .stream()
                    .map(group -> getGroup(group.groupName())).collect(Collectors.toSet()));

            return new UserAndGroups() {
                @Override
                public User getUser() {
                    return user;
                }

                @Override
                public Set<Group> getGroups() {
                    return groups;
                }
            };
        } catch(CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getUserAndGroups: " + watch.getDuration());
        }
    }
}
