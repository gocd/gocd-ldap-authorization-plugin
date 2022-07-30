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
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.junit.Test;

import static com.thoughtworks.gocd.authorization.ldap.apacheds.pool.ConnectionPoolFactory.getLdapConnectionPool;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ConnectionPoolFactoryTest extends BaseIntegrationTest {

    @Test
    public void shouldCreateConnectionPoolUsingConnectionConfig() throws Exception {
        final LdapConfiguration ldapConfiguration = ldapConfiguration(new String[]{"ou=system"});
        final LdapConnectionPool ldapConnectionPool = getLdapConnectionPool(new ConnectionConfiguration(ldapConfiguration));

        final LdapConnection connection = ldapConnectionPool.getConnection();

        assertNotNull(connection);
        assertTrue(connection.isConnected());
    }
}
