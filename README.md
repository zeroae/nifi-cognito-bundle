# nifi-cognito-bundle
NiFi Authorization Extension using AWS Cognito

## Build/Install Instructions
1. Ensure you have AWS Credentials available
    ```
    mvn clean install
    ```
2. The binaries are located in `nifi-cognito-nar/target` and `nifi-registry-cognito-assembly`

## Usage
1. Add new `userGroupProvider` and `accessPolicyProvider` elements to `authorizers.xml`.
    ```xml
    <authorizers>
        <!-- 
            The CognitoUserGroupProvider provides User and Group Management backed by AWS Cognito.
   
            - AWS Credentials File - The file where AWS Credentials can be found. If not defined it will use the standard 
                AWS credentials provider path.
   
            - User Pool - The Cognito User Pool Id where to store the Users and Groups
   
            - Add User <user-uuid> - The identity of an initial user to populate the backend.
                NOTE: Any identity mapping rules specified in nifi.properties will also be applied to the user identity,
                so the value should be the unmapped identity.
           
            - Add Group <group-uuid> - The identity of an initial group to populate the backend.
                NOTE: Any identity mapping rules specified in nifi.properties will also be applied to the group identity,
                so the value should be the unmapped identity.
   
            - Add Users To Group <group-uuid> - A comma separated list of user identifiers to add to the given group.
                NOTE: The User Ids *must* be one of the 'Add User <user-uuid>' entries.
        -->
        <userGroupProvider>
            <identifier>cognito-configurable-user-group-provider</identifier>
            <class>co.zeroae.nifi.authorization.cognito.CognitoUserGroupProvider</class>
            <!-- Use this class for the NiFi Registry
            <class>co.zeroae.nifi.registry.authorization.cognito.CognitoUserGroupProvider</class>
            -->
            <property name="AWS Credentials File">./conf/bootstrap-aws.conf</property>
            <property name="User Pool">us-east-1_XXXXXXX</property>
            <property name="Page Size">50</property>
            <property name="Add User <UUID:1>">CN=administrator, OU=NIFI</property>
            <property name="Add User <UUID:2>">CN=localhost, OU=NIFI</property>
            <property name="Add User <UUID:3>">CN=localhost2, OU=NIFI</property>
            <property name="Add Group <UUID:4>">Cluster</property>
            <property name="Add Users To Group <UUID:4>">
                UUID:2,
                UUID:3
            </property>
        </userGroupProvider>
        <!--
        The CognitoAccessPolicyProvider provides Access Policy Management backed by AWS Cognito.
   
            - AWS Credentials File - The file where AWS Credentials can be found. If not defined it will use the standard 
                AWS credentials provider path.
   
            - User Pool - The *same* Cognito User Pool Id where the Users and Groups are stored.
   
            - Tenant Id - An id to attach to every Access Policy stored in the User Pool. Must be the same for nodes 
                of the same cluster. If two clusters share the same tenant id then they will share the access policies.
   
            - User Group Provider - The identifier of the Cognito User Group Provider defined above.
   
            - Initial Admin Identity <user-uuid> - The identity of the initial admin user. The user must already exist
                on the backend. 
                NOTE: Any identity mapping rules specified in nifi.properties will also be applied to the user identity,
                so the value should be the unmapped identity.
           
            - Node Group - The name of a group containing NiFi cluster nodes. 
                The typical use for this is when nodes are dynamically added/removed from the cluster.
                NOTE: Any identity mapping rules specified in nifi.properties will also be applied to the group identity,
                so the value should be the unmapped identity.
        -->
        <accessPolicyProvider>
            <identifier>cognito-access-policy-provider</identifier>
            <class>co.zeroae.nifi.authorization.cognito.CognitoAccessPolicyProvider</class>
            <!-- Use this class for the NiFi Registry
            <class>co.zeroae.nifi.registry.authorization.cognito.CognitoUserGroupProvider</class>
            -->
            <property name="AWS Credentials File">./conf/bootstrap-aws.conf</property>
            <property name="User Pool">us-east-1_edD0TJEd0</property>
            <property name="User Group Provider">cognito-configurable-user-group-provider</property>
            <property name="Initial Admin Identity">CN=administrator, OU=NIFI</property>
            <property name="Node Group">Cluster</property>
        </accessPolicyProvider>
    </authorizers>
    ```
   
2. Updadte `nifi.properties` 
    ```properties
    nifi.nar.library.directory.cognito=<path-to>/nifi-cognito-bundle/nifi-cognito-nar/target
    nifi.security.identity.mapping.pattern.dn=^CN=(.*?), OU=(.*?)$
    nifi.security.identity.mapping.value.dn=$1@$2
    nifi.security.identity.mapping.transform.dn=LOWER
    ```

3. Update `nifi-registry.properties`
    ```properties
    nifi.registry.extension.dir.cognito=<path-to>/nifi-cognito-bundle/nifi-registry-cognito-assembly/target/cognito/lib
    nifi.registry.security.identity.mapping.pattern.dn=^CN=(.*?), OU=(.*?)$
    nifi.registry.security.identity.mapping.value.dn=$1@$2
    nifi.registry.security.identity.mapping.transform.dn=LOWER
    ```
   
4. Start NiFi and the Registry