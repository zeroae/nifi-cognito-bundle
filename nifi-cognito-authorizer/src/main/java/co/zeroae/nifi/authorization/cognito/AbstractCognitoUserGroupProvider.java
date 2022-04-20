package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.AuthorizerConfigurationContext;
import org.apache.nifi.authorization.User;
import org.apache.nifi.authorization.Group;
import org.apache.nifi.authorization.UserGroupProvider;
import org.apache.nifi.authorization.UserGroupProviderInitializationContext;
import org.apache.nifi.authorization.annotation.AuthorizerContext;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.AuthorizerDestructionException;
import org.apache.nifi.authorization.util.IdentityMapping;
import org.apache.nifi.authorization.util.IdentityMappingUtil;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.util.FormatUtils;
import org.apache.nifi.util.NiFiProperties;
import org.apache.nifi.util.StringUtils;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.MessageActionType;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class AbstractCognitoUserGroupProvider implements UserGroupProvider {
    public static final String PROP_AWS_CREDENTIALS_FILE = "AWS Credentials File";
    public static final String PROP_USER_POOL_ID = "User Pool";
    public static final String PROP_PAGE_SIZE = "Page Size";
    public static final String PROP_MESSAGE_ACTION = "Message Action";

    public static final String PROP_ADD_USER_PREFIX = "Add User";
    public static final String PROP_ADD_GROUP_PREFIX = "Add Group";
    public static final String PROP_ADD_USERS_TO_GROUP_PREFIX = "Add Users To Group";

    public static final String IDENTITY_ATTRIBUTE = "email";

    public static final String DEFAULT_PAGE_SIZE = "50";
    public static final int MAX_PAGE_SIZE = 60;

    public static final String ACCESS_POLICY_GROUP_PREFIX = "acl:nfc:";
    public static final String ACCESS_POLICY_FAUX_USER_PREFIX = "grp:";
    public static final String ACCESS_POLICY_FAUX_USER_EMAIL_FORMAT = "%s@group.local";

    static final Pattern INITIAL_USER_IDENTITY_PATTERN = Pattern.compile(
            PROP_ADD_USER_PREFIX + " (?<identifier>\\S+)");
    static final Pattern INITIAL_GROUP_IDENTITY_PATTERN = Pattern.compile(
            PROP_ADD_GROUP_PREFIX + " (?<identifier>\\S+)");
    static final Pattern INITIAL_GROUP_MEMBERS_PATTERN = Pattern.compile(
            PROP_ADD_USERS_TO_GROUP_PREFIX + " (?<identifier>\\S+)");
    static final String ACCESS_KEY_PROPS_NAME = "aws.access.key.id";
    static final String SECRET_KEY_PROPS_NAME = "aws.secret.access.key";

    public static final long MINIMUM_SYNC_INTERVAL_MILLISECONDS = 10_000;

    NiFiProperties properties;

    CognitoIdentityProviderClient cognitoClient;
    String userPoolId;
    int pageSize;
    MessageActionType messageAction;

    Set<User> initialUsers;
    Set<Group> initialGroups;

    boolean addProxyUserPerGroup;
    String proxyUserEmailDomain;

    @AuthorizerContext
    public void setup(NiFiProperties properties) {
        this.properties = properties;
    }

    @Override
    public void initialize(UserGroupProviderInitializationContext initializationContext) throws AuthorizerCreationException {
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        pageSize = Integer.parseInt(getProperty(configurationContext, PROP_PAGE_SIZE, DEFAULT_PAGE_SIZE));
        if (pageSize > MAX_PAGE_SIZE)
            throw new AuthorizerCreationException(String.format("Max page size for Cognito is %d.", MAX_PAGE_SIZE));

        userPoolId = getProperty(configurationContext, PROP_USER_POOL_ID, null);
        if (userPoolId == null)
            throw new AuthorizerCreationException("User Pool must be valid.");

        messageAction = MessageActionType.fromValue(getProperty(configurationContext, PROP_MESSAGE_ACTION, null));

        addProxyUserPerGroup = true;
        proxyUserEmailDomain = ACCESS_POLICY_FAUX_USER_EMAIL_FORMAT;

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

        final Map<String, User> userMap = configurationContext.getProperties().entrySet().stream()
                .map(e -> new AbstractMap.SimpleEntry<>(INITIAL_USER_IDENTITY_PATTERN.matcher(e.getKey()), e.getValue()))
                .filter(e -> e.getKey().matches() && StringUtils.isNotBlank(e.getValue()))
                .map(e -> new AbstractMap.SimpleEntry<>(e.getKey().group("identifier").toLowerCase(), new User.Builder()
                        .identifier(e.getKey().group("identifier").toLowerCase())
                        .identity(IdentityMappingUtil.mapIdentity(e.getValue().trim(), identityMappings))
                        .build()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        initialUsers = Collections.unmodifiableSet(new HashSet<>(userMap.values()));

        final Map<String, Group.Builder> groupMap = configurationContext.getProperties().entrySet().stream()
                .map(e -> new AbstractMap.SimpleEntry<>(INITIAL_GROUP_IDENTITY_PATTERN.matcher(e.getKey()), e.getValue()))
                .filter(e -> e.getKey().matches() && StringUtils.isNotBlank(e.getValue()))
                .map(e -> new AbstractMap.SimpleEntry<>(e.getKey().group("identifier").toLowerCase(), new Group.Builder()
                        .identifier(e.getKey().group("identifier").toLowerCase())
                        .name(IdentityMappingUtil.mapIdentity(e.getValue(), groupMappings))))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        initialGroups = configurationContext.getProperties().entrySet().stream()
                .map(e -> new AbstractMap.SimpleEntry<>(INITIAL_GROUP_MEMBERS_PATTERN.matcher(e.getKey()), e.getValue()))
                .filter(e -> e.getKey().matches() && StringUtils.isNotBlank(e.getValue()))
                .map(e -> new AbstractMap.SimpleEntry<>(e.getKey().group("identifier").toLowerCase(), e.getValue()))
                .filter(e -> groupMap.containsKey(e.getKey()))
                .map(e -> groupMap.get(e.getKey())
                        .addUsers(Stream.of(e.getValue().split(","))
                                .map(String::trim)
                                .filter(userMap::containsKey)
                                .collect(Collectors.toSet()))
                        .build())
                .collect(Collectors.toSet());
        initialGroups = Collections.unmodifiableSet(initialGroups);
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
