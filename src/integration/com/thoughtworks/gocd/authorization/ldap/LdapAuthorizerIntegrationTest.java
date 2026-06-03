/*
 * Copyright 2022 Thoughtworks, Inc.
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
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.thoughtworks.gocd.authorization.ldap.RoleConfigMother.roleConfigWithAttribute;
import static com.thoughtworks.gocd.authorization.ldap.RoleConfigMother.roleConfigWithGroupMembershipFilter;
import static org.assertj.core.api.Assertions.assertThat;

@ApplyLdifFiles(value = "users.ldif", clazz = BaseIntegrationTest.class)
@CreateLdapServer(
        transports =
                {
                        @CreateTransport(protocol = "LDAP", address = "localhost"),
                        @CreateTransport(protocol = "LDAPS", address = "localhost")
                }
)
public class LdapAuthorizerIntegrationTest extends BaseIntegrationTest {

    @Test
    public void shouldAuthorizeUserUsingAttributeNameAndValue() {
        final AuthenticationResponse response = authenticateUser("bford", "bob");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final RoleConfig adminRole = roleConfigWithAttribute("admin", authConfig.getId(), "l", "New York");
        final RoleConfig viewerRole = roleConfigWithAttribute("view", authConfig.getId(), "l", "Chicago");
        final List<RoleConfig> roleConfigs = Arrays.asList(adminRole, viewerRole);

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, roleConfigs);

        assertThat(roles).hasSize(1);
        assertThat(roles).contains("admin");
    }

    @Test
    public void shouldAuthorizeUserUsingGroupMembershipFilter() {
        final AuthenticationResponse response = authenticateUser("sbanks", "sarah");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final RoleConfig adminRole = roleConfigWithGroupMembershipFilter("admin", authConfig.getId(), "(member={dn})", "cn=Admins,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final RoleConfig viewerRole = roleConfigWithGroupMembershipFilter("view", authConfig.getId(), "(member={dn})", "cn=Viewers,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final List<RoleConfig> roleConfigs = Arrays.asList(adminRole, viewerRole);

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, roleConfigs);

        assertThat(roles).hasSize(1);
        assertThat(roles).contains("view");
    }

    @Test
    public void shouldReturnEmptyRoleListIfNoRoleConfigMatchesInLdapServer() {
        final AuthenticationResponse response = authenticateUser("dthorud", "david");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final RoleConfig adminRole = roleConfigWithGroupMembershipFilter("admin", authConfig.getId(), "(member={dn})", "cn=Admins,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final RoleConfig viewerRole = roleConfigWithGroupMembershipFilter("view", authConfig.getId(), "(member={dn})", "cn=Viewers,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final List<RoleConfig> roleConfigs = Arrays.asList(adminRole, viewerRole);

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, roleConfigs);

        assertThat(roles).hasSize(0);
    }

    @Test
    public void shouldReturnEmptyRoleListIfFailedToAuthorizeUser() {
        final AuthenticationResponse response = authenticateUser("dthorud", "david");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final RoleConfig adminRole = roleConfigWithGroupMembershipFilter("admin", authConfig.getId(), "foo={bar}", "cn=Viewers,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
        final List<RoleConfig> roleConfigs = Arrays.asList(adminRole);

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, roleConfigs);

        assertThat(roles).hasSize(0);
    }

    @Test
    public void shouldReturnEmptyRoleListIfNoRoleConfigProvided() {
        final AuthenticationResponse response = authenticateUser("dthorud", "david");
        final AuthConfig authConfig = response.getConfigUsedForAuthentication();

        final Set<String> roles = new LdapAuthorizer().authorize(response.getUser(), authConfig, Collections.emptyList());

        assertThat(roles).hasSize(0);
    }

    private AuthenticationResponse authenticateUser(String username, String password) {
        LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=Enterprise,ou=Principal,ou=system"});
        AuthConfig authConfig = new AuthConfig("admins_auth_config", ldapConfiguration);
        return new LdapAuthenticator().authenticate(new Credentials(username, password), Collections.singletonList(authConfig));
    }
}
