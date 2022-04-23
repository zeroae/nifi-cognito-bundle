package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.AuthorizerConfigurationContext;
import org.apache.nifi.authorization.annotation.AuthorizerContext;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.AuthorizerDestructionException;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.util.FormatUtils;
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
import java.util.Properties;
import java.util.concurrent.TimeUnit;

public abstract class AbstractCognitoProvider {
    public static final String PROP_AWS_CREDENTIALS_FILE = "AWS Credentials File";
    static final String ACCESS_KEY_PROPS_NAME = "aws.access.key.id";
    static final String SECRET_KEY_PROPS_NAME = "aws.secret.access.key";

    public static final int MAX_PAGE_SIZE = 60;
    public static final String PROP_USER_POOL_ID = "User Pool";
    public static final String PROP_TENANT_ID = "Tenant Id";

    // TODO: Get this from UserPool Tag
    public static final String GROUP_PROXY_USER_PREFIX = "grp:";
    public static final String GROUP_PROXY_USER_EMAIL_FORMAT = "%s@group.local";

    public static final long MINIMUM_SYNC_INTERVAL_MILLISECONDS = 10_000;

    NiFiProperties properties;

    CognitoIdentityProviderClient cognitoClient;
    String userPoolId;
    String tenantId;
    int pageSize;

    @AuthorizerContext
    public void setup(NiFiProperties properties) {
        this.properties = properties;
    }

    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        pageSize = MAX_PAGE_SIZE;

        tenantId = getProperty(configurationContext, PROP_TENANT_ID, "");
        if (tenantId.contains(":") || tenantId.length() > 16)
            throw new AuthorizerCreationException("Tenant Id must be less than 16 characters and not container ':'");

        userPoolId = getProperty(configurationContext, PROP_USER_POOL_ID, null);
        if (userPoolId == null)
            throw new AuthorizerCreationException("User Pool must be set.");

        try {
            final String credentialsFile = getProperty(configurationContext, PROP_AWS_CREDENTIALS_FILE, null);
            cognitoClient = configureClient(credentialsFile);
        } catch (IOException e) {
            throw new AuthorizerCreationException(e.getMessage(), e);
        }
    }

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
        final String accessKey = properties.getProperty(AbstractCognitoProvider.ACCESS_KEY_PROPS_NAME);
        final String secretKey = properties.getProperty(AbstractCognitoProvider.SECRET_KEY_PROPS_NAME);
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

    protected long getDelayProperty(AuthorizerConfigurationContext authContext, String propertyName, String defaultValue) {
        final String propertyValue = getProperty(authContext, propertyName, defaultValue);
        final long syncInterval;
        try {
            syncInterval = Math.round(FormatUtils.getPreciseTimeDuration(propertyValue, TimeUnit.MILLISECONDS));
        } catch (final IllegalArgumentException ignored) {
            throw new AuthorizerCreationException(String.format("The %s '%s' is not a valid time interval.", propertyName, propertyValue));
        }

        if (syncInterval < AbstractCognitoProvider.MINIMUM_SYNC_INTERVAL_MILLISECONDS) {
            throw new AuthorizerCreationException(String.format("The %s '%s' is below the minimum value of '%d ms'", propertyName, propertyValue, AbstractCognitoProvider.MINIMUM_SYNC_INTERVAL_MILLISECONDS));
        }
        return syncInterval;
    }
}
