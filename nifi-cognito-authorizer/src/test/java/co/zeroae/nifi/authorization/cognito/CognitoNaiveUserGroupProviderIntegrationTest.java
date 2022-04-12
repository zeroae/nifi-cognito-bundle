/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package co.zeroae.nifi.authorization.cognito;

import org.apache.nifi.authorization.*;
import org.apache.nifi.util.MockPropertyValue;
import org.apache.nifi.util.NiFiProperties;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;


public class CognitoNaiveUserGroupProviderIntegrationTest {
    private static final Logger logger = LoggerFactory.getLogger(CognitoNaiveUserGroupProviderIntegrationTest.class);

    private static final String ADMIN_IDENTITY = "admin@nifi.zeroae.co";
    private static final String NODE1_IDENTITY = "nifi+n1@nifi.zeroae.co";
    private static final String NODE2_IDENTITY = "nifi+n2@nifi.zeroae.co";

    private NiFiProperties properties;
    private AuthorizerConfigurationContext authContext = Mockito.mock(AuthorizerConfigurationContext.class);
    private CognitoNaiveUserGroupProvider testingProvider;
    private UserGroupProviderInitializationContext initContext;

    static CognitoIdentityProviderClient client;
    static UserPoolType userPool;

    @BeforeAll
    public static void beforeAll() {
        client = CognitoIdentityProviderClient.builder()
                .build();

        userPool = client.createUserPool(CreateUserPoolRequest.builder()
                .poolName("nifi-test")
                .adminCreateUserConfig(AdminCreateUserConfigType.builder()
                        .allowAdminCreateUserOnly(true)
                        .build())
                .build()
        ).userPool();

        User administrator = new User.Builder()
                .identifierGenerateRandom()
                .identity(ADMIN_IDENTITY)
                .build();
        User node1 = new User.Builder()
                .identifierGenerateRandom()
                .identity(NODE1_IDENTITY)
                .build();
        User node2 = new User.Builder()
                .identifierGenerateRandom()
                .identity(NODE2_IDENTITY)
                .build();

        Group adminGroup = new Group.Builder()
                .identifierGenerateRandom()
                .name("Administrators")
                .addUser(administrator.getIdentifier())
                .build();
        Group nodeGroup = new Group.Builder()
                .identifierGenerateRandom()
                .name("Node Group")
                .addUser(node1.getIdentifier())
                .addUser(node2.getIdentifier())
                .build();
        Group remoteGroup = new Group.Builder()
                .identifierGenerateRandom()
                .name("Site To Site")
                .addUser(node1.getIdentifier())
                .addUser(node2.getIdentifier())
                .build();

        try {
            for (User u : new User[]{administrator, node1, node2}) {
                client.adminCreateUser(AdminCreateUserRequest.builder()
                        .userPoolId(userPool.id())
                        .username(u.getIdentifier())
                        .userAttributes(
                                AttributeType.builder()
                                        .name("email")
                                        .value(u.getIdentity())
                                        .build()
                        )
                        .build());
            }
            for (Group g : new Group[]{adminGroup, nodeGroup, remoteGroup}) {
                client.createGroup(CreateGroupRequest.builder()
                        .userPoolId(userPool.id())
                        .groupName(g.getIdentifier())
                        .description(g.getName())
                        .build()
                );
                for (String u : g.getUsers()) {
                    client.adminAddUserToGroup(AdminAddUserToGroupRequest.builder()
                            .userPoolId(userPool.id())
                            .groupName(g.getIdentifier())
                            .username(u)
                            .build());
                }
            }
        } catch (final CognitoIdentityProviderException e) {
            client.deleteUserPool(DeleteUserPoolRequest.builder().userPoolId(userPool.id()).build());
            throw e;
        }
    }

    @AfterAll
    public static void afterAll() {
        if (userPool != null) {
            client.deleteUserPool(DeleteUserPoolRequest.builder()
                    .userPoolId(userPool.id())
                    .build()
            );
            userPool = null;
        }
    }

    @BeforeEach
    public void setup() {
        authContext = Mockito.mock(AuthorizerConfigurationContext.class);
        initContext = Mockito.mock(UserGroupProviderInitializationContext.class);

        Mockito.when(authContext.getProperty(Mockito.eq(AbstractCognitoUserGroupProvider.PROP_USER_POOL_ID)))
                .thenReturn(new MockPropertyValue(userPool.id()));
        Mockito.when(authContext.getProperty(Mockito.eq(AbstractCognitoUserGroupProvider.PROP_MESSAGE_ACTION)))
                .thenReturn(new MockPropertyValue("SUPPRESS"));

        properties = mock(NiFiProperties.class);
    }
    private void setupTestingProvider() {
        testingProvider = new CognitoNaiveUserGroupProvider();
        try {
            testingProvider.setup(properties);
            testingProvider.initialize(initContext);
            testingProvider.onConfigured(authContext);
        } catch (final Exception e) {
            logger.error("Error during setup; tests cannot run on this system.", e);
        }
    }

    @AfterEach
    public void tearDown() {
        if (testingProvider != null)  {
            testingProvider.preDestruction();
            testingProvider = null;
        }
    }

    @Test
    public void testGroupPagination() {
        final int pageSize = 1;
        Mockito.when(authContext.getProperty(Mockito.eq(CognitoNaiveUserGroupProvider.PROP_PAGE_SIZE)))
                .thenReturn(new MockPropertyValue(Integer.toString(pageSize)));

        setupTestingProvider();
        Set<Group> groups = testingProvider.getGroups();
        assertTrue(groups.size() > pageSize);
    }

    @Test
    public void testUserPagination() {
        final int pageSize = 1;
        Mockito.when(authContext.getProperty(Mockito.eq(CognitoNaiveUserGroupProvider.PROP_PAGE_SIZE)))
                .thenReturn(new MockPropertyValue(Integer.toString(pageSize)));

        setupTestingProvider();
        int maxUsersInSingleGroup = 0;
        for (Group group : testingProvider.getGroups()) {
            maxUsersInSingleGroup = Integer.max(maxUsersInSingleGroup, group.getUsers().size());
            if (maxUsersInSingleGroup > pageSize)
                break;
        }
        assertTrue(maxUsersInSingleGroup > pageSize, "max(group.users.size) > 1");
    }

    @Test
    public void testGetUserByEmail() {
        setupTestingProvider();
        assertNotNull(testingProvider.getUserByIdentity(ADMIN_IDENTITY));
    }

    @Test
    public void testGetGroupByName() {
        setupTestingProvider();
        assertNotNull(testingProvider.getGroupByName("Administrators"));
    }

    @Test
    public void testGetUserGroups() {
        setupTestingProvider();
        UserAndGroups userAndGroups = testingProvider.getUserAndGroups(NODE1_IDENTITY);
        assertNotNull(userAndGroups);
        assertTrue(userAndGroups.getGroups().size() > 1, "groups.size > 1");
    }

}
