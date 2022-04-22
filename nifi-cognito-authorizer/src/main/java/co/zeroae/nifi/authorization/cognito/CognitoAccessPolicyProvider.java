package co.zeroae.nifi.authorization.cognito;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.apache.nifi.authorization.*;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GroupType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListGroupsRequest;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CognitoAccessPolicyProvider extends CognitoNaiveAccessPolicyProvider {
    LoadingCache<Map.Entry<String, String>, Set<GroupType>> groupTypeCache;
    LoadingCache<String, Optional<AccessPolicy>> policyCache;
    LoadingCache<String, Optional<AccessPolicy>> policyByGroupName;

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        // TODO: Use a Cache Spec String
        policyCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(identifier ->
                        Optional.ofNullable(CognitoAccessPolicyProvider.super.getAccessPolicy(identifier))
                );
        policyByGroupName = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(new AbstractCacheLoaderAll<String, AccessPolicy>() {
                    @Override
                    public Optional<AccessPolicy> load(@NonNull String groupName) {
                        Map.Entry<String, RequestAction> resourceAndAction= getResourceAndAction(groupName);
                        return Optional.ofNullable(CognitoAccessPolicyProvider.super.getAccessPolicy(
                                resourceAndAction.getKey(), resourceAndAction.getValue())
                        );
                    }

                    @Override
                    public Set<AccessPolicy> getAllValues() {
                        return CognitoAccessPolicyProvider.super.getAccessPolicies();
                    }

                    @Override
                    public String getKey(AccessPolicy value) {
                        return getGroupName(value);
                    }
                });
        groupTypeCache = Caffeine.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build(entry -> cognitoClient.listGroupsPaginator(ListGroupsRequest.builder()
                                .userPoolId(entry.getKey())
                                .limit(pageSize)
                                .build())
                        .groups()
                        .stream()
                        .filter(group -> group.groupName().startsWith(entry.getValue()))
                        .collect(Collectors.toSet())
                );

        super.onConfigured(configurationContext);

        Stream.of(
                groupTypeCache, policyCache, policyByGroupName
        ).forEachOrdered(Cache::invalidateAll);
    }

    @Override
    public Set<AccessPolicy> getAccessPolicies() throws AuthorizationAccessException {
        final Set<String> policyGroupNames = Objects.requireNonNull(
                groupTypeCache.get(new AbstractMap.SimpleEntry<>(userPoolId, policyGroupPrefix))).stream()
                .map(GroupType::groupName)
                .collect(Collectors.toSet());
        policyByGroupName.getAll(policyGroupNames);

        final Set<AccessPolicy> rv = policyByGroupName.asMap().values().stream()
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toSet());
        return Collections.unmodifiableSet(rv);
    }

    @Override
    public AccessPolicy getAccessPolicy(String identifier) throws AuthorizationAccessException {
        return Objects.requireNonNull(policyCache.get(identifier)).orElse(null);
    }

    @Override
    public AccessPolicy getAccessPolicy(String resource, RequestAction action) throws AuthorizationAccessException {
        return Objects.requireNonNull(policyByGroupName.get(getGroupName(resource, action))).orElse(null);
    }

    @Override
    public AccessPolicy addAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        try {
            AccessPolicy rv = super.addAccessPolicy(accessPolicy);
            groupTypeCache.invalidateAll();
            return rv;
        } finally {
            invalidate(accessPolicy);
        }
    }

    @Override
    public AccessPolicy updateAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        invalidate(accessPolicy);
        return super.updateAccessPolicy(accessPolicy);
    }

    @Override
    public AccessPolicy deleteAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        try {
            return super.deleteAccessPolicy(accessPolicy);
        } finally {
            invalidate(accessPolicy);
        }
    }

    @Override
    protected void addPrincipalToPolicy(String principalIdentifier, AccessPolicy policy) {
        try {
            super.addPrincipalToPolicy(principalIdentifier, policy);
        } finally {
            invalidate(policy);
        }
    }

    @Override
    protected void removePrincipalFromPolicy(String principalIdentifier, AccessPolicy policy) {
        try {
            super.removePrincipalFromPolicy(principalIdentifier, policy);
        } finally {
            invalidate(policy);
        }
    }

    private void invalidate(AccessPolicy policy) {
        policyCache.invalidate(policy.getIdentifier());
        policyByGroupName.invalidate(getGroupName(policy));
    }
}
