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

import com.thoughtworks.gocd.authorization.ldap.LdapConfigurationMother;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ConnectionConfigurationTest {
    @Test
    public void shouldBuildLdapConnectionConfigFromLdapConfiguration() throws Exception {
        final LdapConfiguration ldapConfiguration = new LdapConfigurationMother.Builder()
                .withURL("ldaps://foo:389")
                .withSearchBases("searchBase")
                .withManagerDN("uid=admin,ou=system")
                .withPassword("secret")
                .build();

        final LdapConnectionConfig ldapConnectionConfig = new ConnectionConfiguration(ldapConfiguration).toLdapConnectionConfig();

        assertThat(ldapConnectionConfig.isUseSsl()).isTrue();
        assertThat(ldapConnectionConfig.getLdapHost()).isEqualTo("foo");
        assertThat(ldapConnectionConfig.getLdapPort()).isEqualTo(389);
        assertThat(ldapConnectionConfig.getName()).isEqualTo("uid=admin,ou=system");
        assertThat(ldapConnectionConfig.getCredentials()).isEqualTo("secret");
        assertThat(ldapConnectionConfig.getTrustManagers().length).isEqualTo(1);
    }

    @Test
    public void shouldHaveAStringRepresentation() throws Exception {
        final LdapConfiguration configuration = new LdapConfigurationMother.Builder().withCertificate("cert").build();

        final ConnectionConfiguration connectionConfiguration = new ConnectionConfiguration(configuration);

        assertThat(connectionConfiguration.toString()).isEqualTo("ConnectionConfiguration{useSsl=false, ldapPort=389, ldapHost='localhost', managerDn='uid=admin,ou=system', password='secret', certString='cert', startTLS=false}");
    }

    @Test
    public void shouldCheckEquality() throws Exception {
        assertThat(new ConnectionConfiguration(new LdapConfigurationMother.Builder().build())).isEqualTo(new ConnectionConfiguration(new LdapConfigurationMother.Builder().build()));

        assertThat(new ConnectionConfiguration(new LdapConfigurationMother.Builder().withURL("ldap://bar").build())
                .equals(new ConnectionConfiguration(new LdapConfigurationMother.Builder().withURL("ldaps://foo").build()))).isFalse();
    }
}
