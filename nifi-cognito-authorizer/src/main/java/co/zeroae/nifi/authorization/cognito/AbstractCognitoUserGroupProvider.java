package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.AuthorizerConfigurationContext;
import org.apache.nifi.authorization.UserGroupProvider;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.AuthorizerDestructionException;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.util.FormatUtils;
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

public abstract class AbstractCognitoUserGroupProvider implements UserGroupProvider {
    public static final String USER_POOL_PROPERTY = "User Pool";
    public static final String IDENTITY_ATTRIBUTE = "email";

    public static final String PAGE_SIZE_PROPERTY = "Page Size";
    public static final String DEFAULT_PAGE_SIZE = "50";
    public static final int MAX_PAGE_SIZE = 60;

    public static final String AWS_CREDENTIALS_FILE_PROPERTY = "AWS Credentials File";
    private static final String ACCESS_KEY_PROPS_NAME = "aws.access.key.id";
    private static final String SECRET_KEY_PROPS_NAME = "aws.secret.access.key";

    public static final long MINIMUM_SYNC_INTERVAL_MILLISECONDS = 10_000;
    CognitoIdentityProviderClient cognitoClient;
    String userPoolId;
    int pageSize;

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        pageSize = Integer.parseInt(getProperty(configurationContext, PAGE_SIZE_PROPERTY, DEFAULT_PAGE_SIZE));
        if (pageSize > MAX_PAGE_SIZE)
            throw new AuthorizerCreationException(String.format("Max page size for Cognito is %d.", MAX_PAGE_SIZE));

        userPoolId = getProperty(configurationContext, USER_POOL_PROPERTY, null);
        if (userPoolId == null)
            throw new AuthorizerCreationException("User Pool must be valid.");

        try {
            final String credentialsFile = getProperty(configurationContext, AWS_CREDENTIALS_FILE_PROPERTY, null);
            cognitoClient = configureClient(credentialsFile);
        } catch (IOException e) {
            throw new AuthorizerCreationException(e.getMessage(), e);
        }
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
        if (isNotBlank(accessKey) && isNotBlank(secretKey))
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

    private static boolean isNotBlank(final String value) {
        return value != null && !value.trim().equals("");
    }

    @Override
    public void preDestruction() throws AuthorizerDestructionException {
        cognitoClient.close();
        userPoolId = null;
        pageSize = 0;
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

        if (syncInterval < AbstractCognitoUserGroupProvider.MINIMUM_SYNC_INTERVAL_MILLISECONDS) {
            throw new AuthorizerCreationException(String.format("The %s '%s' is below the minimum value of '%d ms'", propertyName, propertyValue, AbstractCognitoUserGroupProvider.MINIMUM_SYNC_INTERVAL_MILLISECONDS));
        }
        return syncInterval;
    }
}
