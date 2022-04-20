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
        final Set<AccessPolicy> rv;
        final ListGroupsRequest request = ListGroupsRequest.builder()
                .userPoolId(userPoolId)
                .limit(pageSize)
                .build();
        watch.start();
        try {
            rv = cognitoClient.listGroupsPaginator(request).groups().stream()
                    .filter(group -> group.groupName().startsWith(AbstractCognitoUserGroupProvider.ACCESS_POLICY_GROUP_PREFIX))
                    .map(this::buildAccessPolicy)
                    .collect(Collectors.toSet());
        } catch (CognitoIdentityProviderException e){
            throw new AuthorizationAccessException(e.getMessage(), e);
        } finally {
            watch.stop();
            logger.debug("getAccessPolicies: " + watch.getDuration());
        }
        return Collections.unmodifiableSet(rv);
    }

    @Override
    public AccessPolicy getAccessPolicy(String identifier) throws AuthorizationAccessException {
        StopWatch watch = new StopWatch();
        GetGroupRequest request = GetGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(ensureAccessPolicyIdentifierFormat(identifier))
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
        AccessPolicy.Builder accessPolicyBuilder = new AccessPolicy.Builder()
                .identifier(group.groupName())
                .resource(group.description().split("#", 2)[0])
                .action(RequestAction.valueOfValue(group.description().split("#", 2)[1]));
        getPrincipalsInPolicy(group.groupName()).forEach(principal -> {
            if (principal.startsWith(AbstractCognitoUserGroupProvider.ACCESS_POLICY_FAUX_USER_PREFIX))
                accessPolicyBuilder.addGroup(principal.substring(AbstractCognitoUserGroupProvider.ACCESS_POLICY_FAUX_USER_PREFIX.length()));
            else
                accessPolicyBuilder.addUser(principal);
        });
        return accessPolicyBuilder.build();
    }

    @Override
    public AccessPolicy getAccessPolicy(String resourceIdentifier, RequestAction action) throws AuthorizationAccessException {
        // This is *super inefficient*! We solve it with caching.
        final Set<AccessPolicy> allPolicies = getAccessPolicies();
        if (allPolicies == null)
            return null;

        return allPolicies.stream()
                .filter(policy -> policy.getResource().equals(resourceIdentifier) && policy.getAction() == action)
                .findFirst()
                .orElse(null);
    }

    protected Set<String> getPrincipalsInPolicy(String identifier) throws AuthorizationAccessException {
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
            logger.debug("getPrincipalsInPolicy: " + watch.getDuration());
        }
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
        accessPolicy = ensureAccessPolicyIdentifierFormat(accessPolicy);
        CreateGroupRequest request = CreateGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(accessPolicy.getIdentifier())
                .description(accessPolicy.getResource() + "#" + accessPolicy.getAction())
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

    protected String ensureAccessPolicyIdentifierFormat(String identifier) {
        if (identifier.startsWith(AbstractCognitoUserGroupProvider.ACCESS_POLICY_GROUP_PREFIX))
            return identifier;
        return AbstractCognitoUserGroupProvider.ACCESS_POLICY_GROUP_PREFIX + policyWriteScope + ":" + identifier;

    }
    protected AccessPolicy ensureAccessPolicyIdentifierFormat(AccessPolicy accessPolicy) {
        if (accessPolicy.getIdentifier().startsWith(AbstractCognitoUserGroupProvider.ACCESS_POLICY_GROUP_PREFIX))
            return accessPolicy;
        return new AccessPolicy.Builder()
                .identifier(ensureAccessPolicyIdentifierFormat(accessPolicy.getIdentifier()))
                .resource(accessPolicy.getResource())
                .action(accessPolicy.getAction())
                .addUsers(accessPolicy.getUsers())
                .addGroups(accessPolicy.getGroups())
                .build();
    }

    @Override
    public AccessPolicy updateAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        accessPolicy = ensureAccessPolicyIdentifierFormat(accessPolicy);
        AccessPolicy current = getAccessPolicy(accessPolicy.getIdentifier());

        if (!(current.getResource().equals(accessPolicy.getResource()) && current.getAction().equals(accessPolicy.getAction())))
            throw new UnsupportedOperationException("Cognito can't change resource or action.");

        final Set<String> usersToAdd = new HashSet<>(accessPolicy.getUsers());
        usersToAdd.removeAll(current.getUsers());
        usersToAdd.forEach(user -> addPrincipalToPolicy(user, current.getIdentifier()));

        final Set<String> usersToRemove = new HashSet<>(current.getUsers());
        usersToRemove.removeAll(accessPolicy.getUsers());
        usersToRemove.forEach(user -> removePrincipalFromPolicy(user, current.getIdentifier()));

        final Set<String> groupsToAdd = new HashSet<>(accessPolicy.getGroups());
        groupsToAdd.removeAll(current.getGroups());
        groupsToAdd.forEach(group -> addPrincipalToPolicy(ensureGroupFormat(group), current.getIdentifier()));

        final Set<String> groupsToRemove = new HashSet<>(current.getGroups());
        groupsToRemove.removeAll(accessPolicy.getGroups());
        groupsToRemove.forEach(group -> removePrincipalFromPolicy(ensureGroupFormat(group), current.getIdentifier()));

        return getAccessPolicy(accessPolicy.getIdentifier());
    }

    private String ensureGroupFormat(String group) {
        return group.startsWith(AbstractCognitoUserGroupProvider.ACCESS_POLICY_FAUX_USER_PREFIX) ? group : AbstractCognitoUserGroupProvider.ACCESS_POLICY_FAUX_USER_PREFIX + group;
    }

    @Override
    public AccessPolicy deleteAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        accessPolicy = ensureAccessPolicyIdentifierFormat(accessPolicy);
        DeleteGroupRequest request = DeleteGroupRequest.builder()
                .userPoolId(userPoolId)
                .groupName(accessPolicy.getIdentifier())
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

    protected void removePrincipalFromPolicy(String principalIdentifier, String policyIdentifier) {
        try {
            cognitoClient.adminRemoveUserFromGroup(AdminRemoveUserFromGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(principalIdentifier)
                    .groupName(policyIdentifier)
                    .build());
        } catch (UserNotFoundException e) {
            logger.warn(String.format("Error removing '%s' from policy '%s'. User not found in Cognito",
                    principalIdentifier, policyIdentifier));
        } catch (CognitoIdentityProviderException e) {
            logger.error(String.format("Error removing user %s from policy %s", principalIdentifier, policyIdentifier), e);
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
    }

    protected void addPrincipalToPolicy(String principalIdentifier, String policyIdentifier) {
        try {
            cognitoClient.adminAddUserToGroup(AdminAddUserToGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(principalIdentifier)
                    .groupName(policyIdentifier)
                    .build());
        } catch (UserNotFoundException e) {
            logger.warn(String.format("Not adding principal '%s' to policy '%s'. User was not found in Cognito.",
                    principalIdentifier, policyIdentifier));
        } catch (CognitoIdentityProviderException e) {
            logger.error(String.format("Error adding principal '%s' to group '%s'", principalIdentifier, policyIdentifier), e);
            throw new AuthorizationAccessException(e.getMessage(), e);
        }
    }
}
