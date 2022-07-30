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
import org.apache.directory.ldap.client.template.exception.LdapRuntimeException;
import org.apache.directory.ldap.client.template.exception.PasswordException;
import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.*;;

public class LdapTest extends BaseIntegrationTest {

    @Test
    public void shouldSearchUsingSearchFilter() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        final List<Entry> search = ldap.search("(uid=*{0}*)", new String[]{"bford"}, 0);

        assertNotNull(search);
        assertThat(search, hasSize(1));
        assertThat(search.get(0).getDn(), is("uid=bford,ou=Employees,ou=Enterprise,ou=Principal,ou=system"));
    }

    @Test
    public void shouldLimitSearchResults() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        final List<Entry> search = ldap.search("(uid=*{0}*)", new String[]{"banks"}, 2);

        assertNotNull(search);
        assertThat(search, hasSize(2));

        final List<String> DNs = search.stream().map(e -> e.getDn().toString()).collect(Collectors.toList());

        assertThat(DNs, containsInAnyOrder("uid=pbanks,ou=Employees,ou=Enterprise,ou=Principal,ou=system", "uid=sbanks,ou=Clients,ou=Enterprise,ou=Principal,ou=system"));
    }

    @Test
    public void shouldSearchGroupBasedOnFilter() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        final List<String> searchBases = asList("ou=PrivateGroups,ou=Enterprise,ou=Principal,ou=system", "ou=Groups,ou=Enterprise,ou=Principal,ou=system");

        final List<String> results = ldap.searchGroup(searchBases, "(member=uid=admin,ou=Employees,ou=Enterprise,ou=Principal,ou=system)", entry -> entry.getDn().toString());

        assertNotNull(results);
        assertThat(results, hasSize(3));
        assertThat(results, containsInAnyOrder(
                "cn=PluginDevs,ou=PrivateGroups,ou=Enterprise,ou=Principal,ou=system",
                "cn=GoDevs,ou=PrivateGroups,ou=Enterprise,ou=Principal,ou=system",
                "cn=Admins,ou=Groups,ou=Enterprise,ou=Principal,ou=system"));
    }

    @Test
    public void shouldAuthenticateUser() throws Exception {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);
        final Entry authenticate = ldap.authenticate("bford", "bob", entry -> entry);

        assertNotNull(authenticate);
        assertThat(authenticate.getDn(), is("uid=bford,ou=Employees,ou=Enterprise,ou=Principal,ou=system"));
    }

    @Test
    public void shouldAuthenticateUserWithoutLdaps() throws Exception {
        final LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);
        final Entry authenticate = ldap.authenticate("bford", "bob", entry -> entry);

        assertNotNull(authenticate);
        assertThat(authenticate.getDn(), is("uid=bford,ou=Employees,ou=Enterprise,ou=Principal,ou=system"));
    }

    @Test(expected = LdapRuntimeException.class)
    public void shouldErrorOutForInvalidCertificate() throws PasswordException {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithInvalidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        ldap.authenticate("bford", "bob", entry -> entry);
    }

    @Test(expected = PasswordException.class)
    public void shouldErrorOutIfFailToAuthenticateUser() throws Exception {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});

        final Ldap ldap = new Ldap(ldapConfiguration);

        ldap.authenticate("bford", "invalid-password", entry -> entry);
    }

    @Test(expected = RuntimeException.class)
    public void shouldErrorIfUserNotExistInLdapServer() throws Exception {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});

        final Ldap ldap = new Ldap(ldapConfiguration);

        ldap.authenticate("foo", "bar", entry -> entry);
    }

    @Test
    public void shouldSearchUserFromMultipleSearchBases() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{
                "ou=Employees,ou=Enterprise,ou=Principal,ou=system", "ou=Clients,ou=Enterprise,ou=Principal,ou=system"
        });

        final Ldap ldap = new Ldap(ldapConfiguration);

        final List<Entry> results = ldap.search("(uid=*{0}*)", new String[]{"banks"}, 100);

        assertThat(results, hasSize(2));

        assertThat(results.get(0).getDn().getParent().toString(), is("ou=Employees,ou=Enterprise,ou=Principal,ou=system"));
        assertThat(results.get(1).getDn().getParent().toString(), is("ou=Clients,ou=Enterprise,ou=Principal,ou=system"));
    }

    @Test
    public void shouldSearchUser() {
        final LdapConfiguration ldapConfiguration = ldapConfigurationWithValidCert("ldaps", new String[]{"ou=system"});
        final Ldap ldap = new Ldap(ldapConfiguration);

        Entry user = ldap.searchUser("bford", entry -> entry);

        assertNotNull(user);
        assertThat(user.getDn().getParent().toString(), is("ou=Employees,ou=Enterprise,ou=Principal,ou=system"));
    }
}
