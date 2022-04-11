package co.zeroae.nifi.authorization.cognito;

import dev.failsafe.Failsafe;
import dev.failsafe.Fallback;
import dev.failsafe.RetryPolicy;
import org.apache.nifi.authorization.*;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.UninheritableAuthorizationsException;
import org.apache.nifi.util.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;


import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class CognitoNaiveUserGroupProvider extends AbstractCognitoUserGroupProvider implements ConfigurableUserGroupProvider {
    private final static Logger logger = LoggerFactory.getLogger(CognitoNaiveUserGroupProvider.class);

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        super.onConfigured(configurationContext);

        RetryPolicy<Object> nullRetryPolicy = RetryPolicy.builder()
                .withMaxAttempts(10)
                .withBackoff(Duration.ofMillis(100), Duration.ofSeconds(5))
                .handleResult(null)
                .abortOn(IllegalStateException.class)
                .build();

        initialUserIdentities.stream()
                .filter(user -> getUser(user.getIdentifier()) == null)
                .forEach(user -> {
                    final Fallback<Object> fallback = Fallback.of(() -> getUser(user.getIdentifier()));
                    Objects.requireNonNull(
                            Failsafe.with(fallback)
                                    .compose(nullRetryPolicy)
                                    .get(() -> addUser(user)),
                    "Could not initialize identity " + user);
                });

        initialGroupIdentities.stream()
                .filter(group -> getGroup(group.getIdentifier()) == null)
                .forEach(group -> {
                    final Fallback<Object> fallback = Fallback.of(() -> getGroup(group.getIdentifier()));
                    Objects.requireNonNull(
                            Failsafe.with(fallback)
                                    .compose(nullRetryPolicy)
                                    .get(() -> addGroup(group, false)),
                    "Could not initialize group " + group);
                });

        initialGroupMembers.forEach((group, users) -> users.forEach(user -> addUserToGroup(user, group)));
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
                    userBuilder.identity(attribute.value());
            });
            return userBuilder.build();
        } catch (UserNotFoundException e) {
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

    @Override
    public String getFingerprint() throws AuthorizationAccessException {
        return userPoolId;
    }

    @Override
    public void inheritFingerprint(String fingerprint) throws AuthorizationAccessException {
        checkInheritability(fingerprint);
    }

    @Override
    public void forciblyInheritFingerprint(String fingerprint) throws AuthorizationAccessException {
        checkInheritability(fingerprint);
    }

    @Override
    public void checkInheritability(String proposedFingerprint) throws AuthorizationAccessException, UninheritableAuthorizationsException {
        if (!proposedFingerprint.equals(userPoolId)) {
            throw new UninheritableAuthorizationsException("Inheritance is not supported for different userPoolIds");
        }
    }

    @Override
    public boolean isConfigurable(User user) {
        return getUser(user.getIdentifier()) != null;
    }

    @Override
    public boolean isConfigurable(Group group) {
        return ! group.getIdentifier().startsWith(userPoolId) && getGroup(group.getIdentifier()) != null;
    }

    @Override
    public User addUser(User user) throws AuthorizationAccessException {
        AdminCreateUserRequest request = AdminCreateUserRequest.builder()
                .userPoolId(userPoolId)
                .username(user.getIdentifier())
                .userAttributes(
                        AttributeType.builder().name(IDENTITY_ATTRIBUTE).value(user.getIdentity()).build(),
                        AttributeType.builder().name("email_verified").value(Boolean.TRUE.toString()).build()
                        )
                .forceAliasCreation(false)
                .messageAction(MessageActionType.SUPPRESS) // Do not send an e-mail
                .build();
        try {
            cognitoClient.adminCreateUser(request);
        } catch (AliasExistsException | UsernameExistsException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
        return getUser(user.getIdentifier());
    }

    @Override
    public User updateUser(User user) throws AuthorizationAccessException {
        // To support assigning users to groups in the UI we need the user to be editable.
        if (!getUser(user.getIdentifier()).getIdentity().equals(user.getIdentity()))
            throw new AuthorizationAccessException("Cognito does not support changing the user identity.");
        return getUser(user.getIdentifier());
    }

    @Override
    public User deleteUser(User user) throws AuthorizationAccessException {
        try {
            cognitoClient.adminDisableUser(AdminDisableUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(user.getIdentifier())
                    .build());
            cognitoClient.adminDeleteUser(AdminDeleteUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(user.getIdentifier())
                    .build());
        } catch (final UserNotFoundException e) {
            return null;
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
        return user;
    }

    @Override
    public Group addGroup(Group group) throws AuthorizationAccessException {
        return addGroup(group, true);
    }

    protected Group addGroup(Group group, boolean setUsers) {
        CreateGroupRequest request = CreateGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(group.getIdentifier())
                .description(group.getName())
                .build();
        try {
            cognitoClient.createGroup(request);
        } catch (GroupExistsException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (CognitoIdentityProviderException e) {
            logger.error("Error creating group: " + group.getName());
            throw new AuthorizationAccessException("Error creating group: " + group.getName(), e);
        }
        return setUsers ? updateGroup(group) : group;
    }

    @Override
    public Group updateGroup(Group group) throws AuthorizationAccessException {
        Group current = getGroup(group.getIdentifier());

        if (!current.getName().equals(group.getName()))
            throw new AuthorizationAccessException("Cognito does not support changing group names.");

        final Set<String> usersToAdd = new HashSet<>(group.getUsers());
        usersToAdd.removeAll(current.getUsers());
        usersToAdd.forEach(user -> addUserToGroup(user, current.getIdentifier()));

        final Set<String> usersToRemove = new HashSet<>(current.getUsers());
        usersToRemove.removeAll(group.getUsers());
        usersToRemove.forEach(user -> removeUserFromGroup(user, current.getIdentifier()));

        return getGroup(group.getIdentifier());
    }

    protected void removeUserFromGroup(String userIdentifier, String groupIdentifier) {
        try {
            cognitoClient.adminRemoveUserFromGroup(AdminRemoveUserFromGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(userIdentifier)
                    .groupName(groupIdentifier)
                    .build());
        } catch (UserNotFoundException e) {
            logger.warn(String.format("Error removing '%s' from group '%s'. User not found in Cognito",
                    userIdentifier, groupIdentifier));
        } catch (CognitoIdentityProviderException e) {
            logger.error(String.format("Error removing user %s from group %s", userIdentifier, groupIdentifier), e);
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
    }

    protected void addUserToGroup(String userIdentifier, String groupIdentifier) {
        try {
            cognitoClient.adminAddUserToGroup(AdminAddUserToGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(userIdentifier)
                    .groupName(groupIdentifier)
                    .build());
        } catch (UserNotFoundException e) {
            logger.warn(String.format("Not adding '%s' to group '%s'. User was not found in Cognito.",
                    userIdentifier, groupIdentifier));
        } catch (CognitoIdentityProviderException e) {
            logger.error(String.format("Error adding user %s to group %s", userIdentifier, groupIdentifier), e);
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
    }

    @Override
    public Group deleteGroup(Group group) throws AuthorizationAccessException {
        DeleteGroupRequest request = DeleteGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(group.getIdentifier())
                .build();
        try {
            cognitoClient.deleteGroup(request);
        } catch (final ResourceNotFoundException e ) {
            return null;
        } catch (final CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException("Error deleting group: " + group.getName(), e);
        }
        return group;
    }
}
