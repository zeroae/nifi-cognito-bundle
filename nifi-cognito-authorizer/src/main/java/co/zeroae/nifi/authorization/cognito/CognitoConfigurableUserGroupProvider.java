package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.ConfigurableUserGroupProvider;
import org.apache.nifi.authorization.Group;
import org.apache.nifi.authorization.User;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.UninheritableAuthorizationsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class CognitoConfigurableUserGroupProvider extends CognitoCaffeineUserGroupProvider implements ConfigurableUserGroupProvider {
    private final static Logger logger = LoggerFactory.getLogger(CognitoConfigurableUserGroupProvider.class);

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
            usersCache.invalidate(user.getIdentifier());
            userByIdentityCache.invalidate(user.getIdentity());
            userAndGroupsCache.invalidate(user.getIdentity());
        } catch (AliasExistsException e) {
            throw new IllegalStateException(e);
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
        return getUser(user.getIdentifier());
    }

    @Override
    public boolean isConfigurable(User user) {
        return getUser(user.getIdentifier()) != null;
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
        Set<Group> userGroups = getUserAndGroups(user.getIdentity()).getGroups();
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
        } finally {
            usersCache.invalidate(user.getIdentifier());
            userByIdentityCache.invalidate(user.getIdentity());
            userAndGroupsCache.invalidate(user.getIdentity());
            groupsCache.invalidateAll(userGroups.stream().map(Group::getIdentifier).collect(Collectors.toSet()));
        }
        return user;
    }

    @Override
    public Group addGroup(Group group) throws AuthorizationAccessException {
        CreateGroupRequest request = CreateGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(group.getIdentifier())
                .description(group.getName())
                .build();
        try {
            cognitoClient.createGroup(request);
            groupsCache.invalidate(group.getIdentifier());
        } catch (GroupExistsException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (CognitoIdentityProviderException e) {
            logger.error("Error creating group: " + group.getName());
            throw new AuthorizationAccessException("Error creating group: " + group.getName(), e);
        }
        return updateGroup(group);
    }

    @Override
    public boolean isConfigurable(Group group) {
        return ! group.getIdentifier().startsWith(userPoolId) && getGroup(group.getIdentifier()) != null;
    }

    @Override
    public Group updateGroup(Group group) throws AuthorizationAccessException {
        Group current = getGroup(group.getIdentifier());

        if (!current.getName().equals(group.getName()))
            throw new AuthorizationAccessException("Cognito does not support changing group names.");

        final Set<String> usersToAdd = new HashSet<>(group.getUsers());
        usersToAdd.removeAll(current.getUsers());

        final Set<String> usersToRemove = new HashSet<>(current.getUsers());
        usersToRemove.removeAll(group.getUsers());

        usersToAdd.forEach(user -> {
            try {
                cognitoClient.adminAddUserToGroup(AdminAddUserToGroupRequest.builder()
                        .userPoolId(userPoolId)
                        .username(user)
                        .groupName(current.getIdentifier())
                        .build());
                groupsCache.invalidate(current.getIdentifier());
            } catch (UserNotFoundException e) {
                logger.warn(String.format("Not adding '%s' to group '%s'. User was not found in Cognito.",
                        user, current.getName()));
            } catch (CognitoIdentityProviderException e) {
                logger.error(String.format("Error adding user %s to group %s", user, current.getName()), e);
                throw new AuthorizationAccessException(e.getMessage(), e);
            }
        });
        usersToRemove.forEach(user -> {
            try {
                cognitoClient.adminRemoveUserFromGroup(AdminRemoveUserFromGroupRequest.builder()
                        .userPoolId(userPoolId)
                        .username(user)
                        .groupName(current.getIdentifier())
                        .build());
            } catch (UserNotFoundException e) {
                logger.warn(String.format("Error removing '%s' from group '%s'. User not found in Cognito",
                        user, current.getName()));
            } catch (CognitoIdentityProviderException e) {
                logger.error(String.format("Error removing user %s from group %s", user, current.getName()), e);
                throw new AuthorizationAccessException(e.getMessage(), e);
            } finally {
                groupsCache.invalidate(current.getIdentifier());
                userAndGroupsCache.invalidate(getUser(user).getIdentity());
            }
        });
        return getGroup(group.getIdentifier());
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
        } finally {
            groupsCache.invalidate(group.getIdentifier());
        }
        return group;
    }
}
