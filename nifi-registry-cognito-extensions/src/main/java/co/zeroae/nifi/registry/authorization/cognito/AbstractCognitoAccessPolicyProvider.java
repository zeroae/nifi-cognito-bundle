package co.zeroae.nifi.registry.authorization.cognito;

import org.apache.nifi.registry.properties.NiFiRegistryProperties;
import org.apache.nifi.registry.properties.util.IdentityMapping;
import org.apache.nifi.registry.properties.util.IdentityMappingUtil;
import org.apache.nifi.registry.security.authorization.*;
import org.apache.nifi.registry.security.authorization.annotation.AuthorizerContext;
import org.apache.nifi.registry.security.exception.SecurityProviderCreationException;
import org.apache.nifi.registry.security.exception.SecurityProviderDestructionException;
import org.apache.nifi.registry.util.PropertyValue;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.utils.StringUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

public abstract class AbstractCognitoAccessPolicyProvider implements AccessPolicyProvider {
    public static final String PROP_AWS_CREDENTIALS_FILE = "AWS Credentials File";
    public static final String PROP_USER_POOL_ID = "User Pool";
    public static final String PROP_USER_GROUP_PROVIDER = "User Group Provider";
    public static final String PROP_INITIAL_ADMIN_IDENTITY = "Initial Admin Identity";
    public static final String PROP_INITIAL_ADMIN_GROUP = "Admin Group";
    public static final String PROP_NODE_GROUP_NAME = "Node Group";

    public static final int MAX_PAGE_SIZE = 60;

    public static final String ACCESS_POLICY_GROUP_PREFIX =
            AbstractCognitoUserGroupProvider.EXCLUDE_GROUP_PREFIX + "nfr:";

    static final String ACCESS_KEY_PROPS_NAME = "aws.access.key.id";
    static final String SECRET_KEY_PROPS_NAME = "aws.secret.access.key";

    NiFiRegistryProperties properties;
    UserGroupProviderLookup userGroupProviderLookup;

    UserGroupProvider userGroupProvider;

    CognitoIdentityProviderClient cognitoClient;
    String userPoolId;
    int pageSize;

    User initialAdmin;
    Group initialAdminGroup;
    Group initialNodeGroup;

    String policyGroupPrefix;

    @AuthorizerContext
    public void setup(NiFiRegistryProperties properties) { this.properties = properties; }

    @Override
    public UserGroupProvider getUserGroupProvider() {
        return userGroupProvider;
    }

    @Override
    public void initialize(AccessPolicyProviderInitializationContext initializationContext) throws SecurityProviderCreationException {
        userGroupProviderLookup = initializationContext.getUserGroupProviderLookup();
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws SecurityProviderCreationException {
        final PropertyValue userGroupProviderIdentifier = configurationContext.getProperty(PROP_USER_GROUP_PROVIDER);
        if (!userGroupProviderIdentifier.isSet())
            throw new SecurityProviderCreationException("The user group provider must be specified");

        userGroupProvider = userGroupProviderLookup.getUserGroupProvider(userGroupProviderIdentifier.getValue());
        if (userGroupProvider == null)
            throw new SecurityProviderCreationException("Unable to locate user group provider with identifier " + userGroupProviderIdentifier.getValue());

        pageSize = MAX_PAGE_SIZE;

        userPoolId = getProperty(configurationContext, PROP_USER_POOL_ID, null);
        if (userPoolId == null)
            throw new SecurityProviderCreationException("User Pool must be valid.");

        policyGroupPrefix = ACCESS_POLICY_GROUP_PREFIX + "";

        try {
            final String credentialsFile = getProperty(configurationContext, PROP_AWS_CREDENTIALS_FILE, null);
            cognitoClient = configureClient(credentialsFile);
        } catch (IOException e) {
            throw new SecurityProviderCreationException(e.getMessage(), e);
        }

        // extract any new identities
        final List<IdentityMapping> identityMappings = Collections.unmodifiableList(
                IdentityMappingUtil.getIdentityMappings(properties));
        final List<IdentityMapping> groupMappings = Collections.unmodifiableList(
                IdentityMappingUtil.getGroupMappings(properties));

        // get the value of the initial admin identity
        final PropertyValue initialAdminIdentityProp = configurationContext.getProperty(PROP_INITIAL_ADMIN_IDENTITY);
        final String initialAdminIdentity = initialAdminIdentityProp.isSet() ? IdentityMappingUtil.mapIdentity(
                initialAdminIdentityProp.getValue(), identityMappings
        ) : null;
        if (initialAdminIdentity != null)
            initialAdmin = userGroupProvider.getUserByIdentity(initialAdminIdentity);

        // get the value of the initial admin group
        final PropertyValue initialAdminGroupProp = configurationContext.getProperty(PROP_INITIAL_ADMIN_GROUP);
        final String initialAdminGroupIdentity = initialAdminGroupProp.isSet() ? IdentityMappingUtil.mapIdentity(
                initialAdminGroupProp.getValue(), groupMappings
        ) : null;
        if (initialAdminGroupIdentity != null)
            initialAdminGroup = userGroupProvider.getGroups().stream()
                    .filter(group -> group.getName().equals(initialAdminGroupIdentity))
                    .findFirst()
                    .orElse(null);

        // extract any node groups
        final PropertyValue initialNodeGroupProp = configurationContext.getProperty(PROP_NODE_GROUP_NAME);
        final String initialNodeGroupIdentity = initialNodeGroupProp.isSet() ? IdentityMappingUtil.mapIdentity(
                initialNodeGroupProp.getValue(), groupMappings
        ) : null;
        if (initialNodeGroupIdentity != null)
            initialNodeGroup = userGroupProvider.getGroups().stream()
                    .filter(group -> group.getName().equals(initialNodeGroupIdentity))
                    .findFirst()
                    .orElse(null);
    }

    @Override
    public void preDestruction() throws SecurityProviderDestructionException {
        cognitoClient.close();
        userPoolId = null;
        pageSize = 0;
    }

    CognitoIdentityProviderClient configureClient(final String awsCredentialsFilename) throws IOException {
        if (awsCredentialsFilename == null) {
            return getDefaultClient();
        }
        final Properties properties = loadProperties(awsCredentialsFilename);
        final String accessKey = properties.getProperty(ACCESS_KEY_PROPS_NAME);
        final String secretKey = properties.getProperty(SECRET_KEY_PROPS_NAME);
        final Region region = Region.of(userPoolId.substring(0, userPoolId.indexOf('_')));

        AwsBasicCredentials basicCredentials = AwsBasicCredentials.create(accessKey, secretKey);
        if (StringUtils.isNotBlank(accessKey) && StringUtils.isNotBlank(secretKey))
            return CognitoIdentityProviderClient.builder()
                    .region(region)
                    .credentialsProvider(StaticCredentialsProvider.create(basicCredentials))
                    .build();
        else
            return getDefaultClient();
    }

    private CognitoIdentityProviderClient getDefaultClient() {
        return CognitoIdentityProviderClient.builder()
                .region(Region.of(userPoolId.substring(0, userPoolId.indexOf('_'))))
                .build();
    }

    private Properties loadProperties(final String propertiesFilename) throws IOException {
        final Properties properties = new Properties();

        try (final InputStream in = new FileInputStream(Paths.get(propertiesFilename).toFile())) {
            properties.load(in);
            return properties;
        }
    }

    protected String getProperty(AuthorizerConfigurationContext authContext, String propertyName, String defaultValue) {
        final PropertyValue property = authContext.getProperty(propertyName);
        if (property != null && property.isSet()) {
            final String value = property.getValue();
            if (StringUtils.isNotBlank(value)) {
                return value;
            }
        }
        return defaultValue;
    }

}
