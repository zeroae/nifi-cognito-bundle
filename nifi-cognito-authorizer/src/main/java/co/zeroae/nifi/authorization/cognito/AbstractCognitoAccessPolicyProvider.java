package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.*;
import org.apache.nifi.authorization.annotation.AuthorizerContext;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.AuthorizerDestructionException;
import org.apache.nifi.authorization.util.IdentityMapping;
import org.apache.nifi.authorization.util.IdentityMappingUtil;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.util.NiFiProperties;
import org.apache.nifi.util.StringUtils;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.*;

public abstract class AbstractCognitoAccessPolicyProvider implements AccessPolicyProvider {
    public static final String PROP_AWS_CREDENTIALS_FILE = "AWS Credentials File";
    public static final String PROP_USER_POOL_ID = "User Pool";
    public static final String PROP_USER_GROUP_PROVIDER = "User Group Provider";
    public static final String PROP_INITIAL_ADMIN_IDENTITY = "Initial Admin Identity";
    public static final String PROP_NODE_GROUP_NAME = "Node Group";

    public static final int MAX_PAGE_SIZE = 60;

    public static final String ACCESS_POLICY_GROUP_PREFIX =
            AbstractCognitoUserGroupProvider.EXCLUDE_GROUP_PREFIX + "nfc:";

    static final String ACCESS_KEY_PROPS_NAME = "aws.access.key.id";
    static final String SECRET_KEY_PROPS_NAME = "aws.secret.access.key";

    NiFiProperties properties;
    UserGroupProviderLookup userGroupProviderLookup;

    UserGroupProvider userGroupProvider;

    CognitoIdentityProviderClient cognitoClient;
    String userPoolId;
    int pageSize;

    User initialAdmin;
    Group initialNodeGroup;

    String policyGroupPrefix;

    @AuthorizerContext
    public void setup(NiFiProperties properties) { this.properties = properties; }

    @Override
    public UserGroupProvider getUserGroupProvider() {
        return userGroupProvider;
    }

    @Override
    public void initialize(AccessPolicyProviderInitializationContext initializationContext) throws AuthorizerCreationException {
        userGroupProviderLookup = initializationContext.getUserGroupProviderLookup();
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        final PropertyValue  userGroupProviderIdentifier = configurationContext.getProperty(PROP_USER_GROUP_PROVIDER);
        if (!userGroupProviderIdentifier.isSet())
            throw new AuthorizerCreationException("The user group provider must be specified");

        userGroupProvider = userGroupProviderLookup.getUserGroupProvider(userGroupProviderIdentifier.getValue());
        if (userGroupProvider == null)
            throw new AuthorizerCreationException("Unable to locate user group provider with identifier " + userGroupProviderIdentifier.getValue());

        pageSize = MAX_PAGE_SIZE;

        userPoolId = getProperty(configurationContext, PROP_USER_POOL_ID, null);
        if (userPoolId == null)
            throw new AuthorizerCreationException("User Pool must be valid.");

        policyGroupPrefix = ACCESS_POLICY_GROUP_PREFIX + "";

        try {
            final String credentialsFile = getProperty(configurationContext, PROP_AWS_CREDENTIALS_FILE, null);
            cognitoClient = configureClient(credentialsFile);
        } catch (IOException e) {
            throw new AuthorizerCreationException(e.getMessage(), e);
        }

        // extract any new identities
        final List<IdentityMapping> identityMappings = Collections.unmodifiableList(
                IdentityMappingUtil.getIdentityMappings(properties));
        final List<IdentityMapping> groupMappings = Collections.unmodifiableList(
                IdentityMappingUtil.getGroupMappings(properties));

        // get the value of the initial admin identity
        final PropertyValue initialAdminIdentityProp = configurationContext.getProperty(PROP_INITIAL_ADMIN_IDENTITY);
        final String initialAdminIdentity = initialAdminIdentityProp.isSet() ? IdentityMappingUtil.mapIdentity(initialAdminIdentityProp.getValue(), identityMappings) : null;
        if (initialAdminIdentity != null)
            initialAdmin = userGroupProvider.getUserByIdentity(initialAdminIdentity);

        // extract any node identities
        final PropertyValue initialNodeGroupProp = configurationContext.getProperty(PROP_NODE_GROUP_NAME);
        final String initialNodeGroupIdentity = initialNodeGroupProp.isSet() ? IdentityMappingUtil.mapIdentity(initialNodeGroupProp.getValue(), groupMappings) : null;
        if (initialNodeGroupIdentity != null)
            initialNodeGroup = userGroupProvider.getGroupByName(initialNodeGroupIdentity);
    }

    @Override
    public void preDestruction() throws AuthorizerDestructionException {
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
