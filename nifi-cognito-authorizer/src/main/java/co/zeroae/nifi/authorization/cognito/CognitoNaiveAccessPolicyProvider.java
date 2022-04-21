package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.AccessPolicy;
import org.apache.nifi.authorization.ConfigurableAccessPolicyProvider;
import org.apache.nifi.authorization.RequestAction;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.UninheritableAuthorizationsException;
import org.apache.nifi.util.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.lang.UnsupportedOperationException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class CognitoNaiveAccessPolicyProvider extends AbstractCognitoAccessPolicyProvider implements ConfigurableAccessPolicyProvider {
    private final static Logger logger = LoggerFactory.getLogger(CognitoNaiveAccessPolicyProvider.class);


    @Override
    public Set<AccessPolicy> getAccessPolicies() throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        final ListGroupsRequest request = ListGroupsRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .build();
        watch.start();
        try {
            final Set<AccessPolicy> rv = cognitoClient.listGroupsPaginator(request).groups().stream()
                    .filter(group -> group.groupName().startsWith(policyGroupPrefix))
                    .map(this::buildAccessPolicy)
                    .collect(Collectors.toSet());
            return Collections.unmodifiableSet(rv);
        } catch (CognitoIdentityProviderException e){
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getAccessPolicies: " + watch.getDuration());
        }
    }

    @Override
    public AccessPolicy getAccessPolicy(String identifier) throws AuthorizationAccessException {
        final Set<AccessPolicy> allPolicies = getAccessPolicies();
        if (allPolicies == null)
            return null;

        return allPolicies.stream()
                .filter(policy -> policy.getIdentifier().equals(identifier))
                .findFirst()
                .orElse(null);
    }

    @Override
    public AccessPolicy getAccessPolicy(String resource, RequestAction action) throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        GetGroupRequest request = GetGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(getGroupName(resource, action))
                .build();
        watch.start();
        try {
            GroupType group = cognitoClient.getGroup(request).group();
            return buildAccessPolicy(group);
        } catch (ResourceNotFoundException e) {
            return null;
        } catch (CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getAccessPolicy: " + watch.getDuration());
        }
    }

    protected AccessPolicy buildAccessPolicy(GroupType group) {
        logger.debug("Building AccessPolicy from " + group);
        // <acl>:<nfc|nfr>:[id]:<action>:<resource>
        final String[] acl = group.groupName().split(":", 5);
        AccessPolicy.Builder accessPolicyBuilder = new AccessPolicy.Builder()
                .identifier(group.description())
                .resource(acl[4])
                .action(RequestAction.valueOfValue(acl[3]));
        getPrincipalsInPolicy(group).forEach(principal -> {
            if (principal.startsWith(AbstractCognitoUserGroupProvider.GROUP_PROXY_USER_PREFIX))
                accessPolicyBuilder.addGroup(principal.substring(AbstractCognitoUserGroupProvider.GROUP_PROXY_USER_PREFIX.length()));
            else
                accessPolicyBuilder.addUser(principal);
        });
        return accessPolicyBuilder.build();
    }


    protected Set<String> getPrincipalsInPolicy(GroupType groupType) throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        final ListUsersInGroupRequest listUsersInGroupRequest = ListUsersInGroupRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .groupName(groupType.groupName())
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
            logger.debug("getPrincipalsInPolicy: " + watch.getDuration());
        }
    }

    protected String getGroupName(AccessPolicy accessPolicy) {
        return getGroupName(accessPolicy.getResource(), accessPolicy.getAction());
    }

    protected String getGroupName(String resource, RequestAction action) {
        return String.join(":", policyGroupPrefix, action.toString(), resource);
    }

    @Override
    public String getFingerprint() throws AuthorizationAccessException {
        return userPoolId;
    }

    @Override
    public void inheritFingerprint(String fingerprint) throws AuthorizationAccessException {
        // nothing to do, userPoolIds are already the same already!
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
    public AccessPolicy addAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        CreateGroupRequest request = CreateGroupRequest.builder()
                .userPoolId(userPoolId)
                .description(accessPolicy.getIdentifier())
                .groupName(getGroupName(accessPolicy))
                .build();
        try {
            cognitoClient.createGroup(request);
        } catch (GroupExistsException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (CognitoIdentityProviderException e) {
            logger.error("Error creating policy: " + accessPolicy);
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
        return updateAccessPolicy(accessPolicy);
    }


    @Override
    public AccessPolicy updateAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        AccessPolicy current = getAccessPolicy(accessPolicy.getResource(), accessPolicy.getAction());

        if (!(current.getIdentifier().equals(accessPolicy.getIdentifier())))
            throw new UnsupportedOperationException("Cognito can't change policy identifier.");

        final Set<String> usersToAdd = new HashSet<>(accessPolicy.getUsers());
        usersToAdd.removeAll(current.getUsers());
        usersToAdd.forEach(user -> addPrincipalToPolicy(user, current));

        final Set<String> usersToRemove = new HashSet<>(current.getUsers());
        usersToRemove.removeAll(accessPolicy.getUsers());
        usersToRemove.forEach(user -> removePrincipalFromPolicy(user, current));

        final Set<String> groupsToAdd = new HashSet<>(accessPolicy.getGroups());
        groupsToAdd.removeAll(current.getGroups());
        groupsToAdd.forEach(group -> addPrincipalToPolicy(getGroupProxyUsername(group), current));

        final Set<String> groupsToRemove = new HashSet<>(current.getGroups());
        groupsToRemove.removeAll(accessPolicy.getGroups());
        groupsToRemove.forEach(group -> removePrincipalFromPolicy(getGroupProxyUsername(group), current));

        return getAccessPolicy(accessPolicy.getResource(), accessPolicy.getAction());
    }

    private String getGroupProxyUsername(String group) {
        return group.startsWith(AbstractCognitoUserGroupProvider.GROUP_PROXY_USER_PREFIX) ? group : AbstractCognitoUserGroupProvider.GROUP_PROXY_USER_PREFIX + group;
    }

    @Override
    public AccessPolicy deleteAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        DeleteGroupRequest request = DeleteGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(getGroupName(accessPolicy))
                .build();
        try {
            cognitoClient.deleteGroup(request);
        } catch (final ResourceNotFoundException e) {
            return null;
        } catch (final CognitoIdentityProviderException e) {
            throw new AuthorizationAccessException("Error deleting policy: " + accessPolicy, e);
        }
        return accessPolicy;
    }

    protected void removePrincipalFromPolicy(String principalIdentifier, AccessPolicy policy) {
        try {
            cognitoClient.adminRemoveUserFromGroup(AdminRemoveUserFromGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(principalIdentifier)
                    .groupName(getGroupName(policy))
                    .build());
        } catch (UserNotFoundException e) {
            logger.warn(String.format("Error removing '%s' from policy '%s'. User not found in Cognito.",
                    principalIdentifier, policy));
        } catch (CognitoIdentityProviderException e) {
            logger.error(String.format("Error removing user %s from policy %s", principalIdentifier, policy), e);
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
    }

    protected void addPrincipalToPolicy(String principalIdentifier, AccessPolicy policy) {
        try {
            cognitoClient.adminAddUserToGroup(AdminAddUserToGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(principalIdentifier)
                    .groupName(getGroupName(policy))
                    .build());
        } catch (UserNotFoundException e) {
            logger.warn(String.format("Error adding principal '%s' to policy '%s'. User was not found in Cognito.",
                    principalIdentifier, policy));
        } catch (CognitoIdentityProviderException e) {
            logger.error(String.format("Error adding principal '%s' to group '%s'", principalIdentifier, policy), e);
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
    }
}
