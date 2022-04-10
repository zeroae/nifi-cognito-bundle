# nifi-cognito-bundle
NiFi Authorization Extension using AWS Cognito

## Build Instructions
 - Ensure you have AWS Credentials available
    ```
    mvn clean install
    cp nifi-cognito-nar/target/*.nar $NIFI_HOME/extensions
    ```

## Usage
1. Add a new `userGroupProvider` to `authorizers.xml`.
    ```xml
    <authorizers>
       <!-- 
            The CognitoConfigurableUserGroupProvider provides User and Group Management backed by AWS Cognito.
   
            - AWS Credentials File - The file where AWS Credentials can be found. If not defined it will use the standard 
                AWS credentials provider path.
   
            - User Pool - The Cognito User Pool Id where to store the Users and Groups
   
            - Initial Admin Identity [unique key] - The identity of an initial user to populate the backend.
                NOTE: Any identity mapping rules specified in nifi.properties will also be applied to the initial admin identity,
                so the value should be the unmapped identity. This identity must be found in the configured User Group Provider.
   
            - Node Identity - The identity of *this* node. A user with this identity will be created on the backend.
                NOTE: Any identity mapping rules specified in nifi.properties will also be applied to the initial admin identity,
                so the value should be the unmapped identity. This identity must be found in the configured User Group Provider.
   
            - Node Group - The name of the Node Group for this cluster. The Node Identity from above will be added to this group.
                The Node Group name must not include spaces.

        -->
        <userGroupProvider>
            <identifier>cognito-configurable-user-group-provider</identifier>
            <class>co.zeroae.nifi.authorization.cognito.CognitoConfigurableUserGroupProvider</class>
            <property name="AWS Credentials File">./conf/bootstrap-aws.conf</property>
            <property name="User Pool">COGNITO-USER-POOL-ID</property>
            <property name="Page Size">50</property>
            <property name="Initial User Identity 1">CN=administrator, OU=NIFI</property>
            <property name="Node Identity">CN=localhost, OU=NIFI</property>
            <property name="Node Group">Cluster</property>
        </userGroupProvider>
        <accessPolicyProvider>
            <!-- ... -->
            <property name="User Group Provider">cognito-configurable-user-group-provider</property>
            <property name="Node Group">Cluster</property>
            <!-- ... -->
        </accessPolicyProvider>
    </authorizers>
    ```
2. Configure an Identity Mapping in `nifi.properties`
    ```properties
    nifi.security.identity.mapping.pattern.dn=^CN=(.*?), OU=(.*?)$
    nifi.security.identity.mapping.value.dn=$1@$2
    nifi.security.identity.mapping.transform.dn=LOWER
    ```
3. Start NiFi