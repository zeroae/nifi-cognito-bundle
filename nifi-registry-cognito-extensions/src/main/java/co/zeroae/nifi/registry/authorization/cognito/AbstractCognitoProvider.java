package co.zeroae.nifi.registry.authorization.cognito;

import org.apache.nifi.registry.properties.NiFiRegistryProperties;
import org.apache.nifi.registry.security.authorization.AuthorizerConfigurationContext;
import org.apache.nifi.registry.security.authorization.annotation.AuthorizerContext;
import org.apache.nifi.registry.security.exception.SecurityProviderCreationException;
import org.apache.nifi.registry.security.exception.SecurityProviderDestructionException;
import org.apache.nifi.registry.util.FormatUtils;
import org.apache.nifi.registry.util.PropertyValue;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryMode;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.core.retry.backoff.BackoffStrategy;
import software.amazon.awssdk.core.retry.backoff.FullJitterBackoffStrategy;
import software.amazon.awssdk.core.retry.conditions.OrRetryCondition;
import software.amazon.awssdk.core.retry.conditions.RetryCondition;
import software.amazon.awssdk.core.retry.conditions.RetryOnExceptionsCondition;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.TooManyRequestsException;
import software.amazon.awssdk.utils.StringUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

public abstract class AbstractCognitoProvider {
    public static final String PROP_AWS_CREDENTIALS_FILE = "AWS Credentials File";
    static final String ACCESS_KEY_PROPS_NAME = "aws.access.key.id";
    static final String SECRET_KEY_PROPS_NAME = "aws.secret.access.key";

    public static final int MAX_ATTEMPTS = BackoffStrategy.RETRIES_ATTEMPTED_CEILING;
    public static final int MAX_PAGE_SIZE = 60;
    public static final String PROP_USER_POOL_ID = "User Pool";
    public static final String PROP_TENANT_ID = "Tenant Id";

    public static final String GROUP_PROXY_USER_PREFIX = "grp:";
    public static final String GROUP_PROXY_USER_EMAIL_FORMAT = "%s@group.local";

    public static final long MINIMUM_SYNC_INTERVAL_MILLISECONDS = 10_000;

    NiFiRegistryProperties properties;

    CognitoIdentityProviderClient cognitoClient;
    String userPoolId;
    String tenantId;
    int pageSize;

    @AuthorizerContext
    public void setup(NiFiRegistryProperties properties) {
        this.properties = properties;
    }


    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws SecurityProviderCreationException {
        pageSize = MAX_PAGE_SIZE;

        tenantId = getProperty(configurationContext, PROP_TENANT_ID, "");
        if (tenantId.contains(":") || tenantId.length() > 16)
            throw new SecurityProviderCreationException("Tenant Id must be less than 16 characters and must not include ':'");

        userPoolId = getProperty(configurationContext, PROP_USER_POOL_ID, null);
        if (userPoolId == null)
            throw new SecurityProviderCreationException("User Pool must be set.");

        try {
            final String credentialsFile = getProperty(configurationContext, PROP_AWS_CREDENTIALS_FILE, null);
            cognitoClient = configureClient(credentialsFile);
        } catch (IOException e) {
            throw new SecurityProviderCreationException(e.getMessage(), e);
        }
    }

    public void preDestruction() throws SecurityProviderDestructionException {
        cognitoClient.close();
        userPoolId = null;
        pageSize = 0;
    }

    CognitoIdentityProviderClient configureClient(final String awsCredentialsFilename) throws IOException {
        final AwsCredentialsProvider credentialsProvider;
        if (awsCredentialsFilename != null) {
            final Properties properties = loadProperties(awsCredentialsFilename);
            final String accessKey = properties.getProperty(AbstractCognitoProvider.ACCESS_KEY_PROPS_NAME);
            final String secretKey = properties.getProperty(AbstractCognitoProvider.SECRET_KEY_PROPS_NAME);
            if (org.apache.nifi.util.StringUtils.isNotBlank(accessKey) && org.apache.nifi.util.StringUtils.isNotBlank(secretKey)) {
                final AwsBasicCredentials basicCredentials = AwsBasicCredentials.create(accessKey, secretKey);
                credentialsProvider = StaticCredentialsProvider.create(basicCredentials);
            } else {
                credentialsProvider = DefaultCredentialsProvider.create();
            }
        } else {
            credentialsProvider = DefaultCredentialsProvider.create();
        }
        final Region region = Region.of(userPoolId.substring(0, userPoolId.indexOf('_')));
        final RetryPolicy retryPolicy = RetryPolicy.builder(RetryMode.ADAPTIVE)
                .additionalRetryConditionsAllowed(true)
                .fastFailRateLimiting(false)
                .numRetries(Math.min(MAX_ATTEMPTS, BackoffStrategy.RETRIES_ATTEMPTED_CEILING))
                .retryCondition(OrRetryCondition.create(
                        RetryOnExceptionsCondition.create(TooManyRequestsException.class),
                        RetryCondition.defaultRetryCondition()
                ))
                .backoffStrategy(FullJitterBackoffStrategy.builder()
                        .maxBackoffTime(Duration.ofSeconds(30))
                        .baseDelay(Duration.ofMillis(500))
                        .build())
                .throttlingBackoffStrategy(FullJitterBackoffStrategy.builder()
                                .maxBackoffTime(Duration.ofSeconds(30))
                                .baseDelay(Duration.ofMillis(500))
                                .build()
                )
                .build();
        final ClientOverrideConfiguration overrideConfiguration = ClientOverrideConfiguration.builder()
                .retryPolicy(retryPolicy)
                .build();

        return CognitoIdentityProviderClient.builder()
                .region(region)
                .credentialsProvider(credentialsProvider)
                .overrideConfiguration(overrideConfiguration)
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
            throw new SecurityProviderCreationException(String.format("The %s '%s' is not a valid time interval.", propertyName, propertyValue));
        }

        if (syncInterval < AbstractCognitoProvider.MINIMUM_SYNC_INTERVAL_MILLISECONDS) {
            throw new SecurityProviderCreationException(String.format("The %s '%s' is below the minimum value of '%d ms'", propertyName, propertyValue, AbstractCognitoProvider.MINIMUM_SYNC_INTERVAL_MILLISECONDS));
        }
        return syncInterval;
    }
}
