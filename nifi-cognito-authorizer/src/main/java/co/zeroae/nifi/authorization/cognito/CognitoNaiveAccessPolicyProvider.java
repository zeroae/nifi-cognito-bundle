package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.*;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.UninheritableAuthorizationsException;
import org.apache.nifi.authorization.resource.ResourceType;
import org.apache.nifi.authorization.util.IdentityMapping;
import org.apache.nifi.authorization.util.IdentityMappingUtil;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.util.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.lang.UnsupportedOperationException;
import java.util.*;
import java.util.stream.Collectors;

public class CognitoNaiveAccessPolicyProvider extends AbstractCognitoProvider
        implements ConfigurableAccessPolicyProvider {
    private static final Logger logger = LoggerFactory.getLogger(CognitoNaiveAccessPolicyProvider.class);

    public static final String PROP_USER_GROUP_PROVIDER = "User Group Provider";
    public static final String PROP_INITIAL_ADMIN_IDENTITY = "Initial Admin Identity";
    public static final String PROP_INITIAL_ADMIN_GROUP = "Admin Group";
    public static final String PROP_NODE_GROUP_NAME = "Node Group";

    private static final String ACCESS_POLICY_GROUP_PREFIX =
            CognitoUserGroupProvider.EXCLUDE_GROUP_PREFIX + "nfc:";

    UserGroupProviderLookup userGroupProviderLookup;
    UserGroupProvider userGroupProvider;

    String policyGroupPrefix;

    User initialAdmin;
    Group initialAdminGroup;
    Group initialNodeGroup;

    @Override
    public void initialize(AccessPolicyProviderInitializationContext initializationContext) throws AuthorizerCreationException {
        userGroupProviderLookup = initializationContext.getUserGroupProviderLookup();
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        super.onConfigured(configurationContext);

        policyGroupPrefix = ACCESS_POLICY_GROUP_PREFIX + tenantId + ":";

        final PropertyValue userGroupProviderIdentifier = configurationContext.getProperty(PROP_USER_GROUP_PROVIDER);
        if (!userGroupProviderIdentifier.isSet())
            throw new AuthorizerCreationException("The user group provider must be specified");

        userGroupProvider = userGroupProviderLookup.getUserGroupProvider(userGroupProviderIdentifier.getValue());
        if (userGroupProvider == null)
            throw new AuthorizerCreationException("Unable to locate user group provider with identifier " + userGroupProviderIdentifier.getValue());

        // Get the Identity and Group Mappings
        final List<IdentityMapping> identityMappings = Collections.unmodifiableList(
                IdentityMappingUtil.getIdentityMappings(properties));
        final List<IdentityMapping> groupMappings = Collections.unmodifiableList(
                IdentityMappingUtil.getGroupMappings(properties));

        // get the value of the initial admin identity
        final PropertyValue initialAdminIdentityProp = configurationContext.getProperty(PROP_INITIAL_ADMIN_IDENTITY);
        final String initialAdminIdentity = initialAdminIdentityProp.isSet() ? IdentityMappingUtil.mapIdentity(
                initialAdminIdentityProp.getValue(), identityMappings) : null;
        if (initialAdminIdentity != null)
            initialAdmin = userGroupProvider.getUserByIdentity(initialAdminIdentity);

        // get the value of the initial admin group
        final PropertyValue initialAdminGroupProp = configurationContext.getProperty(PROP_INITIAL_ADMIN_GROUP);
        final String initialAdminGroupIdentity = initialAdminGroupProp.isSet() ? IdentityMappingUtil.mapIdentity(
                initialAdminGroupProp.getValue(), groupMappings) : null;
        if (initialAdminGroupIdentity != null)
            initialAdminGroup = userGroupProvider.getGroupByName(initialAdminGroupIdentity);

        // get the value of the initial node group
        final PropertyValue initialNodeGroupProp = configurationContext.getProperty(PROP_NODE_GROUP_NAME);
        final String initialNodeGroupIdentity = initialNodeGroupProp.isSet() ? IdentityMappingUtil.mapIdentity(
                initialNodeGroupProp.getValue(), groupMappings) : null;
        if (initialNodeGroupIdentity != null)
            initialNodeGroup = userGroupProvider.getGroupByName(initialNodeGroupIdentity);

        createInitialPolicies();
    }

    protected void createInitialPolicies() {
        StopWatch watch = new StopWatch();
        watch.start();

        final List<RequestAction> write = Collections.singletonList(RequestAction.WRITE);
        final List<RequestAction> read = Collections.singletonList(RequestAction.READ);
        final List<RequestAction> all = Arrays.asList(RequestAction.READ, RequestAction.WRITE);

        Map<ResourceType, List<RequestAction>> nodePolicies = Collections.unmodifiableMap(new HashMap<ResourceType, List<RequestAction>>() {{
            put(ResourceType.Proxy, write);
            put(ResourceType.SiteToSite, read);
        }});
        Map<ResourceType, List<RequestAction>> adminPolicies = Collections.unmodifiableMap(new HashMap<ResourceType, List<RequestAction>>() {{
            put(ResourceType.Flow, read);
            put(ResourceType.RestrictedComponents, write);
            put(ResourceType.Tenant, all);
            put(ResourceType.Policy, all);
            put(ResourceType.Controller, all);
        }});

        final Map<String, Map<ResourceType, List<RequestAction>>> initialPolicies = new HashMap<>();
        if (initialNodeGroup != null)
            initialPolicies.put(getGroupProxyUsername(initialNodeGroup.getIdentifier()), nodePolicies);

        if (initialAdmin != null)
            initialPolicies.put(initialAdmin.getIdentifier(), adminPolicies);

        if (initialAdminGroup != null)
            initialPolicies.put(getGroupProxyUsername(initialAdminGroup.getIdentifier()), adminPolicies);

        initialPolicies.forEach((principal, value) -> value.entrySet().stream()
                .map(entry -> entry.getValue().stream()
                        .map(action -> new AccessPolicy.Builder()
                                .identifierGenerateRandom()
                                .resource(entry.getKey().getValue())
                                .action(action)
                                .build()
                        ).collect(Collectors.toList()))
                .flatMap(Collection::stream)
                .map(policy -> {
                    final AccessPolicy rv = getAccessPolicy(policy.getResource(), policy.getAction());
                    return rv == null ? addAccessPolicy(policy, false) : rv;
                })
                .forEach(policy -> addPrincipalToPolicy(principal, policy)));

        watch.stop();
        logger.info("Initial Policies created: " + watch.getDuration());
    }

    @Override
    public UserGroupProvider getUserGroupProvider() {
        return userGroupProvider;
    }

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
        Map.Entry<String, RequestAction> resourceAndAction = getResourceAndAction(group.groupName());
        AccessPolicy.Builder accessPolicyBuilder = new AccessPolicy.Builder()
                .identifier(group.description())
                .resource(resourceAndAction.getKey())
                .action(resourceAndAction.getValue());
        getPrincipalsInPolicy(group).forEach(principal -> {
            if (principal.startsWith(GROUP_PROXY_USER_PREFIX))
                accessPolicyBuilder.addGroup(principal.substring(GROUP_PROXY_USER_PREFIX.length()));
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
        return policyGroupPrefix + action + ":" + resource;
    }

    protected Map.Entry<String, RequestAction> getResourceAndAction(String groupName) {
        // <acl>:<nfc|nfr>:[cluster-id|registry-id]:<action>:<resource>
        final String[] acl = groupName.split(":", 5);
        return new AbstractMap.SimpleEntry<>(acl[4], RequestAction.valueOfValue(acl[3]));
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
        return addAccessPolicy(accessPolicy, true);
    }

    private AccessPolicy addAccessPolicy(AccessPolicy accessPolicy, boolean setPrincipals) {
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
        return setPrincipals ? updateAccessPolicy(accessPolicy) : accessPolicy;
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

    private String getGroupProxyUsername(String groupIdentifier) {
        return groupIdentifier.startsWith(GROUP_PROXY_USER_PREFIX)
                ? groupIdentifier
                : GROUP_PROXY_USER_PREFIX + groupIdentifier;
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
