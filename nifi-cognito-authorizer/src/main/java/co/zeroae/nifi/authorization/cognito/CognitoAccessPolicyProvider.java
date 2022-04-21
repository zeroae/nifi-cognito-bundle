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

    LoadingCache<String, Set<GroupType>> groupTypeCache;
    LoadingCache<String, Optional<AccessPolicy>> policyCache;
    LoadingCache<Map.Entry<String, RequestAction>, Optional<AccessPolicy>> policyByResourceAndAction;

    @Override
    public void initialize(AccessPolicyProviderInitializationContext initializationContext) throws AuthorizerCreationException {
        super.initialize(initializationContext);
        // TODO: Use a Cache Spec String
        policyCache = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(new AbstractCacheLoaderAll<String, AccessPolicy>() {
                    @Override
                    public Optional<AccessPolicy> load(@NonNull String key) {
                        return Optional.ofNullable(CognitoAccessPolicyProvider.super.getAccessPolicy(key));
                    }

                    @Override
                    public Set<AccessPolicy> getAllValues() {
                        return CognitoAccessPolicyProvider.super.getAccessPolicies();
                    }

                    @Override
                    public String getKey(AccessPolicy value) {
                        return value.getIdentifier();
                    }
                });
        policyByResourceAndAction = Caffeine.newBuilder()
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(entry ->
                        Optional.ofNullable(CognitoAccessPolicyProvider.super.getAccessPolicy(entry.getKey(), entry.getValue()))
                );
        groupTypeCache = Caffeine.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build(userPoolId -> cognitoClient.listGroupsPaginator(ListGroupsRequest.builder()
                                .userPoolId(userPoolId)
                                .limit(pageSize)
                                .build())
                        .groups()
                        .stream()
                        .filter(group -> group.groupName().startsWith(
                                AbstractCognitoAccessPolicyProvider.ACCESS_POLICY_GROUP_PREFIX))
                        .collect(Collectors.toSet())
                );
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        super.onConfigured(configurationContext);
        Stream.of(
                groupTypeCache, policyCache, policyByResourceAndAction
        ).forEachOrdered(Cache::invalidateAll);
    }

    @Override
    public Set<AccessPolicy> getAccessPolicies() throws AuthorizationAccessException {
        final Set<String> policyNames = Objects.requireNonNull(groupTypeCache.get(userPoolId))
                .stream()
                .map(GroupType::groupName)
                .collect(Collectors.toSet());
        policyCache.getAll(policyNames);

        final Set<AccessPolicy> rv = policyCache.asMap().values().stream()
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
    public AccessPolicy getAccessPolicy(String resourceIdentifier, RequestAction action) throws AuthorizationAccessException {
        return Objects.requireNonNull(policyByResourceAndAction.get(
                new AbstractMap.SimpleEntry<>(resourceIdentifier, action)
        )).orElse(null);
    }

    @Override
    public AccessPolicy addAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        final AccessPolicy rv = super.addAccessPolicy(accessPolicy);
        policyCache.invalidate(rv.getIdentifier());
        policyByResourceAndAction.invalidate(new AbstractMap.SimpleEntry<>(rv.getResource(), rv.getAction()));
        return rv;
    }

    @Override
    public AccessPolicy updateAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        policyCache.invalidate(accessPolicy.getIdentifier());
        policyByResourceAndAction.invalidate(new AbstractMap.SimpleEntry<>(accessPolicy.getResource(), accessPolicy.getAction()));
        return super.updateAccessPolicy(accessPolicy);
    }

    @Override
    public AccessPolicy deleteAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        AccessPolicy rv = null;
        try {
            rv = super.deleteAccessPolicy(accessPolicy);
            return rv;
        } finally {
            final String identifier = rv == null ? accessPolicy.getIdentifier() : rv.getIdentifier();
            final Map.Entry<String, RequestAction> resourceAction = new AbstractMap.SimpleEntry<>(
                    rv == null ? accessPolicy.getResource() : rv.getResource(),
                    rv == null ? accessPolicy.getAction() : rv.getAction()
            );
            policyCache.invalidate(identifier);
            policyByResourceAndAction.invalidate(resourceAction);
        }
    }

    @Override
    protected void addPrincipalToPolicy(String principalIdentifier, String policyIdentifier) {
        super.addPrincipalToPolicy(principalIdentifier, policyIdentifier);
        policyCache.invalidate(policyIdentifier);
    }

    @Override
    protected void removePrincipalFromPolicy(String principalIdentifier, String policyIdentifier) {
        try {
            super.removePrincipalFromPolicy(principalIdentifier, policyIdentifier);
        } finally {
            policyCache.invalidate(policyIdentifier);
        }
    }
}
