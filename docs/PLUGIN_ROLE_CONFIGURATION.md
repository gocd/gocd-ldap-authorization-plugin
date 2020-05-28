# Plugin Role Configuration

The `Plugin Role Config` is used to define roles in GoCD and configure them to map to LDAP/AD groups. LDAP/AD groups can be mapped to GoCD roles using either the combination of `UserGroupMembershipAttribute and GroupIdentifiers` or `GroupMembershipFilter and GroupSearchBases`. In order to create a plugin role, an [authorization configuration](AUTHORIZATION_CONFIGURATION.md) must exist first.

1. Login to the GoCD server as administrator and navigate to **_Admin_** _>_ **_Security_** _>_ **_Role Configuration_**. <br/>
2. Click on **_Add_** to create new role configuration. <br/>
3. For a role type, select **_Plugin Role_**
4. Specify a role name,
5. For **_Auth Config Id_**, select the authorization config you created earlier. For instance, it might show up as `my-ldap (LDAP Authorization Plugin for GoCD)` if the ID you provided was `my-ldap`.

## Map Roles Using Group Membership Attribute On User
This allows you to define a role which will be assigned to the logged in user, only if logged in user is has the given attribute and matching value in their LDAP/AD records.

* **UserGroupMembershipAttribute & GroupIdentifiers:** These properties can be used to map LDAP/AD groups to GoCD role for LDAP/AD servers where the group information is available as part of the user entry.

    ![Map Roles Using Group Membership Attribute On User](images/group-membership-attribute.png?raw=true)

    ```xml
    <pluginRole name="go-admins" authConfigId="my-ldap">
      <property>
        <key>UserGroupMembershipAttribute</key>
        <value>memberOf</value>
      </property>
      <property>
        <key>GroupIdentifiers</key>
        <value>CN=GoAdmins,OU=Groups,OU=Enterprise,OU=Principal,DC=corporate,DC=example,DC=com</value>
      </property>
    </pluginRole>
    ```

    In the above example, all user entries in LDAP/AD having the `memberOf` attribute with value `CN=GoAdmins,OU=Groups,OU=Enterprise,OU=Principal,DC=corporate,DC=example,DC=com` would have a GoCD `go-admins` role.

## Map Roles Using Group Membership Filter
* **GroupMembershipFilter & GroupSearchBases:** These properties can be used to map LDAP/AD groups to GoCD role for LDAP/AD servers where user's record does not contain enough information about group membership. For instance, in absence of `memberOf` overlay in LDAP/AD servers. <br/><br/>The plugin performs a search in LDAP/AD server using `GroupMembershipFilter` and if the search succeeds, the user will be assigned the specified GoCD role. Providing the `GroupSearchBase` would narrow down the `GroupMembershipFilter` search.

    ![Map Roles Using Group Membership Filter](images/group-membership-filter.png?raw=true)

    ```xml
    <pluginRole name="view_user" authConfigId="tw-ldap">
      <property>
        <key>GroupSearchBases</key>
        <value>
          OU=Group-1,OU=Enterprise,OU=Principal,DC=corporate,DC=example,DC=com
          OU=Group-2,OU=Enterprise,OU=Principal,DC=corporate,DC=example,DC=com
        </value>
      </property>
      <property>
        <key>GroupMembershipFilter</key>
        <value>(|(member={dn}) (uniqueMember=name={name}) (memberUid=uid={uid}))</value>
      </property>
    </pluginRole>
    ```

    In the above example for an user entry with following attributes,
    - dn   -> `dn=cn=bob,ou=system,dc=example,dc=com`
    - name -> `Bob Ford`
    - uid  -> `bford`

    the GroupMembershipFilter will resolve to `(| (member=cn=bob,ou=system,dc=example,dc=com) (uniqueMember=name=Bob Ford) (memberUid=uid=bford))`

    **Note:** A GroupMembershipFilter expression with a non-existent user attribute will be invalid. For instance, the expression `(|(member={custom_dn}) (uniqueMember=name={emp_name}))` would be termed invalid if the user entry in LDAP/AD does not have either of the attributes `custom_dn` or `emp_name`.

## Miscellaneous

You can also create a plugin role by configuring both `GroupMembershipAttribute` and `GroupMembershipFilter`. In such a case:

* The plugin makes a role assignment based on `GroupMembershipAttribute` first.
* If a role is not assigned to a user using `GroupMembershipAttribute`, then the plugin checks the `GroupMembershipFilter` to  assign a role.

See [Scenario 7](EXAMPLES.md#scenario-7) in examples section for more information.

## Example role configuration

![Plugin role configuration](images/plugin-role-configuration.png?raw=true)

<hr/>

**Alternatively, the configuration can be added directly to the GoCD config XML using the `<pluginRole>`. It  should be added in `<security>` under `<roles/>` tag as described in following example -**

```xml
<security>
  <authConfigs>
    <authConfig id="my-ldap" pluginId="com.thoughtworks.gocd.authorization.ldap">
      ...
    </authConfig>
  </authConfigs>
  <roles>
    <pluginRole name="go-admins" authConfigId="ldap">
      <property>
        <key>UserGroupMembershipAttribute</key>
        <value>memberOf</value>
      </property>
      <property>
        <key>GroupIdentifiers</key>
        <value>CN=GoAdmins,OU=Groups,OU=Enterprise,OU=Principal,DC=corporate,DC=example,DC=com</value>
      </property>
    </pluginRole>
    <pluginRole name="view_user" authConfigId="tw-ldap">
      <property>
        <key>GroupSearchBases</key>
        <value>
          OU=Group-1,OU=Enterprise,OU=Principal,DC=corporate,DC=example,DC=com
          OU=Group-2,OU=Enterprise,OU=Principal,DC=corporate,DC=example,DC=com
        </value>
      </property>
      <property>
        <key>GroupMembershipFilter</key>
        <value>(|(member={dn}) (uniqueMember=name={name}) (memberUid=uid={uid}))</value>
      </property>
    </pluginRole>
  </roles>
</security>
```
