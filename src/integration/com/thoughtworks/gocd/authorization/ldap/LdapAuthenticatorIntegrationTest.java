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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

@ApplyLdifFiles(value = "users.ldif", clazz = BaseIntegrationTest.class)
@CreateLdapServer(
        transports =
                {
                        @CreateTransport(protocol = "LDAP", address = "localhost"),
                        @CreateTransport(protocol = "LDAPS", address = "localhost")
                },
        keyStore = "./src/testdata/ldap.jks",
        certificatePassword = "secret",
        saslHost = "localhost"
)
public class LdapAuthenticatorIntegrationTest extends BaseIntegrationTest {

    @Test
    public void shouldAuthenticateUser() throws Exception {
        LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=system"});
        AuthConfig authConfig = new AuthConfig("auth_config", ldapConfiguration);

        final Credentials credentials = new Credentials("bford", "bob");

        final AuthenticationResponse response = new LdapAuthenticator().authenticate(credentials, Collections.singletonList(authConfig));

        assertNotNull(response);
        assertThat(response.getUser()).isEqualTo(new User("bford", "Bob Ford", "bford@example.com"));
        assertThat(response.getConfigUsedForAuthentication()).isEqualTo(authConfig);
    }

    @Test
    public void shouldAuthenticateAgainstMultipleSearchBases() throws Exception {
        LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=Employees,ou=Enterprise,ou=Principal,ou=system", "ou=Clients,ou=Enterprise,ou=Principal,ou=system"});

        AuthConfig authConfig = new AuthConfig("auth_config", ldapConfiguration);

        final Credentials credentials = new Credentials("sbanks", "sarah");

        final AuthenticationResponse response = new LdapAuthenticator().authenticate(credentials, Collections.singletonList(authConfig));

        assertNotNull(response);
        assertThat(response.getUser()).isEqualTo(new User("sbanks", "S.Banks", "sbanks@example.com"));
        assertThat(response.getConfigUsedForAuthentication()).isEqualTo(authConfig);
        assertThat(response.getUser().getEntry().getDn().getParent().toString()).endsWith("ou=Clients,ou=Enterprise,ou=Principal,ou=system");
    }

    @Test
    public void shouldAuthenticateAgainstMultipleAuthConfig() throws Exception {
        AuthConfig authConfigForEmployees = new AuthConfig("auth_config_employees", ldapConfiguration(new String[]{"ou=Employees,ou=Enterprise,ou=Principal,ou=system"}));
        AuthConfig authConfigForClients = new AuthConfig("auth_config_clients", ldapConfiguration(new String[]{"ou=Clients,ou=Enterprise,ou=Principal,ou=system"}));

        final Credentials credentials = new Credentials("sbanks", "sarah");

        final AuthenticationResponse response = new LdapAuthenticator().authenticate(credentials, Arrays.asList(authConfigForEmployees, authConfigForClients));

        assertNotNull(response);
        assertThat(response.getUser()).isEqualTo(new User("sbanks", "S.Banks", "sbanks@example.com"));
        assertThat(response.getConfigUsedForAuthentication()).isEqualTo(authConfigForClients);
        assertThat(response.getUser().getEntry().getDn().getParent().toString()).endsWith("ou=Clients,ou=Enterprise,ou=Principal,ou=system");
    }

    @Test
    public void shouldReturnNullIfUserDoesNotExistInLdap() throws Exception {
        LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=system"});
        AuthConfig authConfig = new AuthConfig("auth_config", ldapConfiguration);

        final Credentials credentials = new Credentials("foo", "bar");

        final AuthenticationResponse response = new LdapAuthenticator().authenticate(credentials, Collections.singletonList(authConfig));

        assertNull(response);
    }

    @Test
    public void shouldReturnNullIfNoPasswordProvided() throws Exception {
        LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=system"});
        AuthConfig authConfig = new AuthConfig("auth_config", ldapConfiguration);

        final Credentials credentials = new Credentials("nopasswd", "");

        final AuthenticationResponse response = new LdapAuthenticator().authenticate(credentials, Collections.singletonList(authConfig));

        assertNull(response);
    }

    @Test
    public void searchUser_shouldSearchAndReturnExistingUser() {
        LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=system"});
        AuthConfig authConfig = new AuthConfig("auth_config", ldapConfiguration);

        final AuthenticationResponse response = new LdapAuthenticator().searchUser("bford", Collections.singletonList(authConfig));

        assertNotNull(response);
        assertThat(response.getUser()).isEqualTo(new User("bford", "Bob Ford", "bford@example.com"));
        assertThat(response.getConfigUsedForAuthentication()).isEqualTo(authConfig);
    }

    @Test
    public void searchUser_shouldReturnNullWhenUserDoesNotExist() {
        LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=system"});
        AuthConfig authConfig = new AuthConfig("auth_config", ldapConfiguration);

        final AuthenticationResponse response = new LdapAuthenticator().searchUser("non_existin_user", Collections.singletonList(authConfig));

        assertNull(response);
    }
}
