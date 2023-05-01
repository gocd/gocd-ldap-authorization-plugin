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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

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
        assertThat(ldapConfiguration.getUrl()).isEqualTo("ldap://localhost:10389");
        assertThat(ldapConfiguration.getSearchBases()).contains("ou=users,ou=system", "ou=employee,ou=system");
        assertThat(ldapConfiguration.getManagerDn()).isEqualTo("uid=admin,ou=system");
        assertThat(ldapConfiguration.getPassword()).isEqualTo("secret");
        assertThat(ldapConfiguration.getUserLoginFilter()).isEqualTo("(uid={0})");
        assertThat(ldapConfiguration.getDisplayNameAttribute()).isEqualTo("displayName");
        assertThat(ldapConfiguration.getEmailAttribute()).isEqualTo("mail");
        assertThat(ldapConfiguration.getUserSearchFilter()).isEqualTo("(cn={0})");
        assertThat(ldapConfiguration.getSearchTimeout()).isEqualTo(10);
        assertTrue(ldapConfiguration.startTLS());
    }

    @Test
    public void shouldDeserializeToLdapConfigurationWithDefaultValues() throws Exception {
        LdapConfiguration ldapConfiguration = LdapConfiguration.fromJSON("{}");

        assertNotNull(ldapConfiguration);
        assertThat(ldapConfiguration.getDisplayNameAttribute()).isEqualTo("cn");
        assertThat(ldapConfiguration.getEmailAttribute()).isEqualTo("mail");
        assertThat(ldapConfiguration.getUserSearchFilter()).isEqualTo("(|(sAMAccountName=*{0}*)(uid=*{0}*)(cn=*{0}*)(mail=*{0}*)(otherMailbox=*{0}*))");
        assertThat(ldapConfiguration.getSearchTimeout()).isEqualTo(5);
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
        assertThat(ldapConfiguration.getUserLoginFilter()).isEqualTo("(uid={0})");
        assertThat(ldapConfiguration.getUserSearchFilter()).isEqualTo("(cn={0})");
    }
}
