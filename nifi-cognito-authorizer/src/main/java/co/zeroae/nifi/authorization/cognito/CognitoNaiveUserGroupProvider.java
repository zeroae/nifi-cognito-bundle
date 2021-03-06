package co.zeroae.nifi.authorization.cognito;

import dev.failsafe.Failsafe;
import dev.failsafe.Fallback;
import dev.failsafe.RetryPolicy;
import org.apache.nifi.authorization.*;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.UninheritableAuthorizationsException;
import org.apache.nifi.authorization.util.IdentityMapping;
import org.apache.nifi.authorization.util.IdentityMappingUtil;
import org.apache.nifi.util.StopWatch;
import org.apache.nifi.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;


import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CognitoNaiveUserGroupProvider extends AbstractCognitoProvider implements ConfigurableUserGroupProvider {
    private static final Logger logger = LoggerFactory.getLogger(CognitoNaiveUserGroupProvider.class);

    public static final String PROP_MESSAGE_ACTION = "Message Action";

    public static final String PROP_ADD_USER_PREFIX = "Add User";
    public static final String PROP_ADD_GROUP_PREFIX = "Add Group";
    public static final String PROP_ADD_USERS_TO_GROUP_PREFIX = "Add Users To Group";

    public static final String IDENTITY_ATTRIBUTE = "email";

    // TODO: This should come from the userpool itself through Tags!
    //       Accepting it as a configuration option may cause inconsistency in case of misconfiguration across clusters.
    public static final String EXCLUDE_GROUP_PREFIX = "acl:";

    static final Pattern INITIAL_USER_IDENTITY_PATTERN = Pattern.compile(
            PROP_ADD_USER_PREFIX + " (?<identifier>\\S+)");
    static final Pattern INITIAL_GROUP_IDENTITY_PATTERN = Pattern.compile(
            PROP_ADD_GROUP_PREFIX + " (?<identifier>\\S+)");
    static final Pattern INITIAL_GROUP_MEMBERS_PATTERN = Pattern.compile(
            PROP_ADD_USERS_TO_GROUP_PREFIX + " (?<identifier>\\S+)");

    MessageActionType messageAction;

    Set<User> initialUsers;
    Set<Group> initialGroups;

    @Override
    public void initialize(UserGroupProviderInitializationContext initializationContext) throws AuthorizerCreationException {
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        super.onConfigured(configurationContext);

        messageAction = MessageActionType.fromValue(getProperty(configurationContext, PROP_MESSAGE_ACTION, null));

        // get Identity and Group Mappings
        final List<IdentityMapping> identityMappings = Collections.unmodifiableList(
                IdentityMappingUtil.getIdentityMappings(properties));
        final List<IdentityMapping> groupMappings = Collections.unmodifiableList(
                IdentityMappingUtil.getGroupMappings(properties));

        // extract any new identities
        final Map<String, User> userMap = configurationContext.getProperties().entrySet().stream()
                .map(e -> new AbstractMap.SimpleEntry<>(INITIAL_USER_IDENTITY_PATTERN.matcher(e.getKey()), e.getValue()))
                .filter(e -> e.getKey().matches() && StringUtils.isNotBlank(e.getValue()))
                .map(e -> new AbstractMap.SimpleEntry<>(e.getKey().group("identifier").toLowerCase(), new User.Builder()
                        .identifier(e.getKey().group("identifier").toLowerCase())
                        .identity(IdentityMappingUtil.mapIdentity(e.getValue().trim(), identityMappings))
                        .build()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        initialUsers = Collections.unmodifiableSet(new HashSet<>(userMap.values()));

        // extract new groups *and* group membership
        final Map<String, Group.Builder> groupMap = configurationContext.getProperties().entrySet().stream()
                .map(e -> new AbstractMap.SimpleEntry<>(INITIAL_GROUP_IDENTITY_PATTERN.matcher(e.getKey()), e.getValue()))
                .filter(e -> e.getKey().matches() && StringUtils.isNotBlank(e.getValue()))
                .map(e -> new AbstractMap.SimpleEntry<>(e.getKey().group("identifier").toLowerCase(), new Group.Builder()
                        .identifier(e.getKey().group("identifier").toLowerCase())
                        .name(IdentityMappingUtil.mapIdentity(e.getValue(), groupMappings))))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        // extract any initial user to group mappings
        initialGroups = configurationContext.getProperties().entrySet().stream()
                .map(e -> new AbstractMap.SimpleEntry<>(INITIAL_GROUP_MEMBERS_PATTERN.matcher(e.getKey()), e.getValue()))
                .filter(e -> e.getKey().matches() && StringUtils.isNotBlank(e.getValue()))
                .map(e -> new AbstractMap.SimpleEntry<>(e.getKey().group("identifier").toLowerCase(), e.getValue()))
                .filter(e -> groupMap.containsKey(e.getKey()))
                .map(e -> groupMap.get(e.getKey())
                        .addUsers(Stream.of(e.getValue().split(","))
                                .map(String::trim)
                                .filter(userMap::containsKey)
                                .collect(Collectors.toSet()))
                        .build())
                .collect(Collectors.toSet());
        initialGroups = Collections.unmodifiableSet(initialGroups);

        createInitialUsersAndGroups();
    }

    private void createInitialUsersAndGroups() {
        StopWatch watch = new StopWatch();
        watch.start();

        RetryPolicy<Object> nullRetryPolicy = RetryPolicy.builder()
                .withMaxAttempts(10)
                .withBackoff(Duration.ofMillis(100), Duration.ofSeconds(5))
                .handleResult(null)
                .abortOn(IllegalStateException.class)
                .build();
        RetryPolicy<Object> maxRetryPolicy= RetryPolicy.builder()
                .withMaxAttempts(10)
                .withBackoff(Duration.ofMillis(100), Duration.ofSeconds(5))
                .abortOn(IllegalStateException.class)
                .build();

        initialUsers.stream()
                .filter(user -> getUser(user.getIdentifier()) == null)
                .forEach(user -> {
                    // Fallback ensures upstream User matches the local one.
                    final Fallback<Object> fallback = Fallback.of(() -> updateUser(user));
                    Objects.requireNonNull(
                            Failsafe.with(fallback)
                                    .compose(nullRetryPolicy)
                                    .get(() -> addUser(user)),
                    "Could not initialize identity " + user);
                });

        initialGroups.stream()
                .filter(group -> getGroup(group.getIdentifier()) == null)
                .forEach(group -> {
                    // Fallback only gets the current group, no membership updates.
                    final Fallback<Object> fallback = Fallback.of(() -> getGroup(group.getIdentifier()));
                    Objects.requireNonNull(
                            Failsafe.with(fallback)
                                    .compose(nullRetryPolicy)
                                    .get(() -> addGroup(group, false)),
                    "Could not initialize group " + group);
                });

        initialGroups.stream()
                .filter(group -> getGroup(group.getIdentifier()) != null)
                .forEach(group -> group.getUsers().forEach(user -> Failsafe.with(maxRetryPolicy).run(() ->
                        addUserToGroup(user, group.getIdentifier())
                )));
        watch.stop();
        logger.info("Initial Users/Groups created: " + watch.getDuration());
    }

    @Override
    public Set<User> getUsers() throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        final ListUsersRequest request = ListUsersRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .attributesToGet(IDENTITY_ATTRIBUTE)
                .build();
        watch.start();
        try {
            final Set<User> rv = cognitoClient.listUsersPaginator(request).users().stream()
                    .filter(user -> !user.username().startsWith(GROUP_PROXY_USER_PREFIX))
                    .map(user -> {
                        final User.Builder userBuilder = new User.Builder()
                                .identifier(user.username());
                        user.attributes().forEach(attribute -> {
                            if (attribute.name().equals(IDENTITY_ATTRIBUTE))
                                userBuilder.identity(attribute.value());
                        });
                        return userBuilder.build();
                    }).collect(Collectors.toSet());
            return Collections.unmodifiableSet(rv);
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getUsers: " + watch.getDuration());
        }
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
        final Set<Group> rv;
        final ListGroupsRequest listGroupsRequest = ListGroupsRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .build();
        watch.start();
        try {
            rv = cognitoClient.listGroupsPaginator(listGroupsRequest).groups().stream()
                    .filter(group -> !group.groupName().startsWith(EXCLUDE_GROUP_PREFIX))
                    .map(group -> new Group.Builder()
                            .identifier(group.groupName())
                            .name(group.description())
                            .addUsers(getUsersInGroup(group.groupName()))
                            .build())
                    .collect(Collectors.toSet());
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
            return new Group.Builder()
                    .identifier(group.groupName())
                    .name(group.description())
                    .addUsers(getUsersInGroup(identifier)).build();
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
                    .filter(group -> !group.groupName().startsWith(EXCLUDE_GROUP_PREFIX))
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
                .messageAction(messageAction)
                .desiredDeliveryMediums(DeliveryMediumType.EMAIL)
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
        final String proxyUsername = GROUP_PROXY_USER_PREFIX + group.getIdentifier();
        CreateGroupRequest request = CreateGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(group.getIdentifier())
                .description(group.getName())
                .build();
        AdminCreateUserRequest adminCreateUserRequest = AdminCreateUserRequest.builder()
                .userPoolId(userPoolId)
                .username(proxyUsername)
                .userAttributes(
                        AttributeType.builder().name(IDENTITY_ATTRIBUTE).value(String.format(
                                GROUP_PROXY_USER_EMAIL_FORMAT, group.getIdentifier())).build(),
                        AttributeType.builder().name("email_verified").value("true").build())
                .forceAliasCreation(false)
                .messageAction(MessageActionType.SUPPRESS)
                .build();
        try {
            cognitoClient.adminCreateUser(adminCreateUserRequest);
            cognitoClient.createGroup(request);
        } catch (AliasExistsException | UsernameExistsException | GroupExistsException e) {
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
        final String proxyUsername = GROUP_PROXY_USER_PREFIX + group.getIdentifier();
        DeleteGroupRequest request = DeleteGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(group.getIdentifier())
                .build();
        try {
            cognitoClient.deleteGroup(request);
            cognitoClient.adminDisableUser(AdminDisableUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(proxyUsername)
                    .build());
            cognitoClient.adminDeleteUser(AdminDeleteUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(proxyUsername)
                    .build());
        } catch (final ResourceNotFoundException | UserNotFoundException e ) {
            return null;
        } catch (final CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException("Error deleting group: " + group.getName(), e);
        }
        return group;
    }
}
