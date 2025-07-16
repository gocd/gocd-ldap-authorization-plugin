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

package com.thoughtworks.gocd.authorization.ldap.apacheds;

import com.thoughtworks.gocd.authorization.ldap.BaseIntegrationTest;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapTlsHandshakeException;
import org.apache.directory.ldap.client.template.exception.LdapRuntimeException;
import org.apache.directory.ldap.client.template.exception.PasswordException;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;
import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
public class LdapTest extends BaseIntegrationTest {

    @Test
    public void shouldSearchUsingSearchFilter() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        final List<Entry> search = ldap.search("(uid=*{0}*)", new String[]{"bford"}, 0);

        assertNotNull(search);
        assertThat(search).hasSize(1);
        assertThat(search.get(0).getDn()).isEqualTo("uid=bford,ou=Employees,ou=Enterprise,ou=Principal,ou=system");
    }

    @Test
    public void shouldLimitSearchResults() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        final List<Entry> search = ldap.search("(uid=*{0}*)", new String[]{"banks"}, 2);

        assertNotNull(search);
        assertThat(search).hasSize(2);

        final List<String> DNs = search.stream().map(e -> e.getDn().toString()).collect(Collectors.toList());

        assertThat(DNs).containsExactlyInAnyOrder("uid=pbanks,ou=Employees,ou=Enterprise,ou=Principal,ou=system", "uid=sbanks,ou=Clients,ou=Enterprise,ou=Principal,ou=system");
    }

    @Test
    public void shouldSearchGroupBasedOnFilter() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        final List<String> searchBases = asList("ou=PrivateGroups,ou=Enterprise,ou=Principal,ou=system", "ou=Groups,ou=Enterprise,ou=Principal,ou=system");

        final List<String> results = ldap.searchGroup(searchBases, "(member=uid=admin,ou=Employees,ou=Enterprise,ou=Principal,ou=system)", entry -> entry.getDn().toString());

        assertNotNull(results);
        assertThat(results).hasSize(3);
        assertThat(results).containsExactlyInAnyOrder(
                "cn=PluginDevs,ou=PrivateGroups,ou=Enterprise,ou=Principal,ou=system",
                "cn=GoDevs,ou=PrivateGroups,ou=Enterprise,ou=Principal,ou=system",
                "cn=Admins,ou=Groups,ou=Enterprise,ou=Principal,ou=system");
    }

    @Test
    public void shouldAuthenticateUser() throws Exception {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);
        final Entry authenticate = ldap.authenticate("bford", "bob", entry -> entry);

        assertNotNull(authenticate);
        assertThat(authenticate.getDn()).isEqualTo("uid=bford,ou=Employees,ou=Enterprise,ou=Principal,ou=system");
    }

    @Test
    public void shouldAuthenticateUserWithoutLdaps() throws Exception {
        final LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);
        final Entry authenticate = ldap.authenticate("bford", "bob", entry -> entry);

        assertNotNull(authenticate);
        assertThat(authenticate.getDn()).isEqualTo("uid=bford,ou=Employees,ou=Enterprise,ou=Principal,ou=system");
    }

    @Test
    public void shouldErrorOutForInvalidCertificate() throws PasswordException {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithInvalidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        assertThatCode(() -> ldap.authenticate("bford", "bob", entry -> entry))
                .isInstanceOf(LdapRuntimeException.class)
                .hasCauseInstanceOf(LdapTlsHandshakeException.class);
    }

    @Test
    public void shouldErrorOutIfFailToAuthenticateUser() throws Exception {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});

        final Ldap ldap = new Ldap(ldapConfiguration);

        assertThatCode(() -> ldap.authenticate("bford", "wrong-password", entry -> entry))
                .isInstanceOf(PasswordException.class)
                .hasMessageContaining("Cannot authenticate user uid=bford,ou=Employees,ou=Enterprise,ou=Principal,ou=system");
    }

    @Test
    public void shouldErrorIfUserNotExistInLdapServer() throws Exception {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});

        final Ldap ldap = new Ldap(ldapConfiguration);

        assertThatCode(() -> ldap.authenticate("foo", "bar",entry -> entry))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining(format("User foo does not exist in {0}", ldapConfiguration.getLdapUrl().toString()));
    }

    @Test
    public void shouldSearchUserFromMultipleSearchBases() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{
                "ou=Employees,ou=Enterprise,ou=Principal,ou=system", "ou=Clients,ou=Enterprise,ou=Principal,ou=system"
        });

        final Ldap ldap = new Ldap(ldapConfiguration);

        final List<Entry> results = ldap.search("(uid=*{0}*)", new String[]{"banks"}, 100);

        assertThat(results).hasSize(2);

        assertThat(results.get(0).getDn().getParent().toString()).isEqualTo("ou=Employees,ou=Enterprise,ou=Principal,ou=system");
        assertThat(results.get(1).getDn().getParent().toString()).isEqualTo("ou=Clients,ou=Enterprise,ou=Principal,ou=system");
    }

    @Test
    public void shouldSearchUser() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        Entry user = ldap.searchUser("bford", entry -> entry);

        assertNotNull(user);
        assertThat(user.getDn().getParent().toString()).isEqualTo("ou=Employees,ou=Enterprise,ou=Principal,ou=system");
    }
}
