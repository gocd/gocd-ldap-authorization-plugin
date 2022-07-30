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

package com.thoughtworks.gocd.authorization.ldap.model;

import org.junit.Test;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;

public class LdapConfigurationTest {

    @Test
    public void shouldAbleToDeserializeToLdapProfile() throws Exception {
        String json = "{\n" +
                "  \"ManagerDN\": \"uid=admin,ou=system\",\n" +
                "  \"DisplayNameAttribute\": \"displayName\",\n" +
                "  \"SearchBases\": \"ou=users,ou=system\n" +
                "  ou=employee,ou=system\",\n" +
                "  \"UserLoginFilter\": \"(uid={0})\",\n" +
                "  \"UserSearchFilter\": \"(cn={0})\",\n" +
                "  \"Url\": \"ldap://localhost:10389\",\n" +
                "  \"StartTLS\": true,\n" +
                "  \"SearchTimeout\": 10,\n" +
                "  \"Password\": \"secret\"\n" +
                "}";

        LdapConfiguration ldapConfiguration = LdapConfiguration.fromJSON(json);

        assertNotNull(ldapConfiguration);
        assertThat(ldapConfiguration.getUrl(), is("ldap://localhost:10389"));
        assertThat(ldapConfiguration.getSearchBases(), contains("ou=users,ou=system", "ou=employee,ou=system"));
        assertThat(ldapConfiguration.getManagerDn(), is("uid=admin,ou=system"));
        assertThat(ldapConfiguration.getPassword(), is("secret"));
        assertThat(ldapConfiguration.getUserLoginFilter(), is("(uid={0})"));
        assertThat(ldapConfiguration.getDisplayNameAttribute(), is("displayName"));
        assertThat(ldapConfiguration.getEmailAttribute(), is("mail"));
        assertThat(ldapConfiguration.getUserSearchFilter(), is("(cn={0})"));
        assertThat(ldapConfiguration.getSearchTimeout(), is(10));
        assertTrue(ldapConfiguration.startTLS());
    }

    @Test
    public void shouldDeserializeToLdapConfigurationWithDefaultValues() throws Exception {
        LdapConfiguration ldapConfiguration = LdapConfiguration.fromJSON("{}");

        assertNotNull(ldapConfiguration);
        assertThat(ldapConfiguration.getDisplayNameAttribute(), is("cn"));
        assertThat(ldapConfiguration.getEmailAttribute(), is("mail"));
        assertThat(ldapConfiguration.getUserSearchFilter(), is("(|(sAMAccountName=*{0}*)(uid=*{0}*)(cn=*{0}*)(mail=*{0}*)(otherMailbox=*{0}*))"));
        assertThat(ldapConfiguration.getSearchTimeout(), is(5));
        assertFalse(ldapConfiguration.startTLS());
    }

    @Test
    public void shouldEncloseFiltersInParentheses() throws Exception {
        String json = "{\n" +
                "  \"UserLoginFilter\": \"uid={0}\",\n" +
                "  \"UserSearchFilter\": \"cn={0}\"\n" +
                "}";

        LdapConfiguration ldapConfiguration = LdapConfiguration.fromJSON(json);

        assertNotNull(ldapConfiguration);
        assertThat(ldapConfiguration.getUserLoginFilter(), is("(uid={0})"));
        assertThat(ldapConfiguration.getUserSearchFilter(), is("(cn={0})"));
    }
}
