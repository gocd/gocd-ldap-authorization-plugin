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

package com.thoughtworks.gocd.authorization.ldap.apacheds.pool;

import com.thoughtworks.gocd.authorization.ldap.LdapConfigurationMother;
import com.thoughtworks.gocd.authorization.ldap.apacheds.ConnectionConfiguration;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.junit.Test;

import static com.thoughtworks.gocd.authorization.ldap.apacheds.pool.ConnectionPoolFactory.getLdapConnectionPool;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

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
        assertThat(ldapConnectionPool.getLifo(), is(true));
        assertThat(ldapConnectionPool.getMaxActive(), is(250));
        assertThat(ldapConnectionPool.getMaxIdle(), is(50));
        assertThat(ldapConnectionPool.getMaxWait(), is(-1L));
        assertThat(ldapConnectionPool.getMinIdle(), is(0));
        assertThat(ldapConnectionPool.getNumTestsPerEvictionRun(), is(3));
        assertThat(ldapConnectionPool.getSoftMinEvictableIdleTimeMillis(), is(-1L));
        assertThat(ldapConnectionPool.getTimeBetweenEvictionRunsMillis(), is(-1L));
        assertThat(ldapConnectionPool.getMinEvictableIdleTimeMillis(), is(1000 * 60 * 30L));
        assertThat(ldapConnectionPool.getTestOnBorrow(), is(false));
        assertThat(ldapConnectionPool.getTestOnReturn(), is(false));
        assertThat(ldapConnectionPool.getTestWhileIdle(), is(false));
        assertThat(ldapConnectionPool.getWhenExhaustedAction(), is(GenericObjectPool.WHEN_EXHAUSTED_BLOCK));
    }

    @Test
    public void shouldCacheConnectionPoolObjectForAConnectionConfiguration() throws Exception {
        final ConnectionConfiguration connectionConfiguration = new ConnectionConfiguration(new LdapConfigurationMother.Builder().build());

        final LdapConnectionPool ldapConnectionPoolOne = getLdapConnectionPool(connectionConfiguration);
        final LdapConnectionPool ldapConnectionPoolTwo = getLdapConnectionPool(connectionConfiguration);

        assertNotNull(ldapConnectionPoolOne);
        assertThat(ldapConnectionPoolOne, is(ldapConnectionPoolTwo));
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
