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

package com.thoughtworks.gocd.authorization.ldap.apacheds.pool;

import com.thoughtworks.gocd.authorization.ldap.LdapConfigurationMother;
import com.thoughtworks.gocd.authorization.ldap.apacheds.ConnectionConfiguration;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.junit.jupiter.api.Test;

import static com.thoughtworks.gocd.authorization.ldap.apacheds.pool.ConnectionPoolFactory.getLdapConnectionPool;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ConnectionPoolFactoryTest {

    @Test
    public void shouldCreateConnectionPoolUsingConnectionConfiguration() throws Exception {
        final ConnectionConfiguration connectionConfiguration = new ConnectionConfiguration(new LdapConfigurationMother.Builder().build());

        final LdapConnectionPool ldapConnectionPool = getLdapConnectionPool(connectionConfiguration);

        assertNotNull(ldapConnectionPool);
    }

    @Test
    public void shouldCreateConnectionPoolWithDefaultPoolConfig() throws Exception {
        final ConnectionConfiguration connectionConfiguration = new ConnectionConfiguration(new LdapConfigurationMother.Builder().build());

        final LdapConnectionPool ldapConnectionPool = getLdapConnectionPool(connectionConfiguration);

        assertNotNull(ldapConnectionPool);
        assertThat(ldapConnectionPool.getLifo()).isEqualTo(true);
        assertThat(ldapConnectionPool.getMaxActive()).isEqualTo(250);
        assertThat(ldapConnectionPool.getMaxIdle()).isEqualTo(50);
        assertThat(ldapConnectionPool.getMaxWait()).isEqualTo(-1L);
        assertThat(ldapConnectionPool.getMinIdle()).isEqualTo(0);
        assertThat(ldapConnectionPool.getNumTestsPerEvictionRun()).isEqualTo(3);
        assertThat(ldapConnectionPool.getSoftMinEvictableIdleTimeMillis()).isEqualTo(-1L);
        assertThat(ldapConnectionPool.getTimeBetweenEvictionRunsMillis()).isEqualTo(-1L);
        assertThat(ldapConnectionPool.getMinEvictableIdleTimeMillis()).isEqualTo(1000 * 60 * 30L);
        assertThat(ldapConnectionPool.getTestOnBorrow()).isEqualTo(false);
        assertThat(ldapConnectionPool.getTestOnReturn()).isEqualTo(false);
        assertThat(ldapConnectionPool.getTestWhileIdle()).isEqualTo(false);
        assertThat(ldapConnectionPool.getWhenExhaustedAction()).isEqualTo(GenericObjectPool.WHEN_EXHAUSTED_BLOCK);
    }

    @Test
    public void shouldCacheConnectionPoolObjectForAConnectionConfiguration() throws Exception {
        final ConnectionConfiguration connectionConfiguration = new ConnectionConfiguration(new LdapConfigurationMother.Builder().build());

        final LdapConnectionPool ldapConnectionPoolOne = getLdapConnectionPool(connectionConfiguration);
        final LdapConnectionPool ldapConnectionPoolTwo = getLdapConnectionPool(connectionConfiguration);

        assertNotNull(ldapConnectionPoolOne);
        assertThat(ldapConnectionPoolOne).isEqualTo(ldapConnectionPoolTwo);
    }

    @Test
    public void shouldCreateNewLdapConnectionPoolForDifferentConnectionConfig() throws Exception {
        final ConnectionConfiguration configuration = new ConnectionConfiguration(new LdapConfigurationMother.Builder().withURL("ldap://foo").build());
        final ConnectionConfiguration differentConfiguration = new ConnectionConfiguration(new LdapConfigurationMother.Builder().withURL("ldap://bar").build());

        assertNotEquals(configuration, differentConfiguration);

        final LdapConnectionPool ldapConnectionPoolOne = getLdapConnectionPool(configuration);
        final LdapConnectionPool ldapConnectionPoolTwo = getLdapConnectionPool(differentConfiguration);

        assertNotNull(ldapConnectionPoolOne);
        assertNotEquals(ldapConnectionPoolOne, ldapConnectionPoolTwo);
    }
}
