/*
 * Copyright 2020 ThoughtWorks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.thoughtworks.gocd.authorization.ldap;

import com.thoughtworks.gocd.authorization.ldap.model.*;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.thoughtworks.gocd.authorization.ldap.RoleConfigMother.roleConfigWithAttribute;
import static com.thoughtworks.gocd.authorization.ldap.RoleConfigMother.roleConfigWithGroupMembershipFilter;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.*;;

public class LdapAuthorizerIntegrationTest extends BaseIntegrationTest {

    @Test
    public void shouldAuthorizeUserUsingAttributeNameAndValue() throws Exception {
        final AuthenticationResponse response = authenticateUser("bford", "bob");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final RoleConfig adminRole = roleConfigWithAttribute("admin", authConfig.getId(), "l", "New York");
        final RoleConfig viewerRole = roleConfigWithAttribute("view", authConfig.getId(), "l", "Chicago");
        final List<RoleConfig> roleConfigs = Arrays.asList(adminRole, viewerRole);

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, roleConfigs);

        assertThat(roles, hasSize(1));
        assertThat(roles, contains("admin"));
    }

    @Test
    public void shouldAuthorizeUserUsingGroupMembershipFilter() throws Exception {
        final AuthenticationResponse response = authenticateUser("sbanks", "sarah");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final RoleConfig adminRole = roleConfigWithGroupMembershipFilter("admin", authConfig.getId(), "(member={dn})", "cn=Admins,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final RoleConfig viewerRole = roleConfigWithGroupMembershipFilter("view", authConfig.getId(), "(member={dn})", "cn=Viewers,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final List<RoleConfig> roleConfigs = Arrays.asList(adminRole, viewerRole);

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, roleConfigs);

        assertThat(roles, hasSize(1));
        assertThat(roles, contains("view"));
    }

    @Test
    public void shouldReturnEmptyRoleListIfNoRoleConfigMatchesInLdapServer() throws Exception {
        final AuthenticationResponse response = authenticateUser("dthorud", "david");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final RoleConfig adminRole = roleConfigWithGroupMembershipFilter("admin", authConfig.getId(), "(member={dn})", "cn=Admins,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final RoleConfig viewerRole = roleConfigWithGroupMembershipFilter("view", authConfig.getId(), "(member={dn})", "cn=Viewers,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final List<RoleConfig> roleConfigs = Arrays.asList(adminRole, viewerRole);

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, roleConfigs);

        assertThat(roles, hasSize(0));
    }

    @Test
    public void shouldReturnEmptyRoleListIfFailedToAuthorizeUser() throws Exception {
        final AuthenticationResponse response = authenticateUser("dthorud", "david");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final RoleConfig adminRole = roleConfigWithGroupMembershipFilter("admin", authConfig.getId(), "foo={bar}", "cn=Viewers,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final List<RoleConfig> roleConfigs = Arrays.asList(adminRole);

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, roleConfigs);

        assertThat(roles, hasSize(0));
    }

    @Test
    public void shouldReturnEmptyRoleListIfNoRoleConfigProvided() throws Exception {
        final AuthenticationResponse response = authenticateUser("dthorud", "david");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, Collections.emptyList());

        assertThat(roles, hasSize(0));
    }

    private AuthenticationResponse authenticateUser(String username, String password) {
        LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=Enterprise,ou=Principal,ou=system"});
        AuthConfig authConfig = new AuthConfig("admins_auth_config", ldapConfiguration);
        return new LdapAuthenticator().authenticate(new Credentials(username, password), Collections.singletonList(authConfig));
    }
}
