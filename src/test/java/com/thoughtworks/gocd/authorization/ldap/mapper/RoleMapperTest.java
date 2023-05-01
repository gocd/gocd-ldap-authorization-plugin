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

package com.thoughtworks.gocd.authorization.ldap.mapper;

import com.thoughtworks.gocd.authorization.ldap.model.RoleConfig;
import com.thoughtworks.gocd.authorization.ldap.model.RoleConfiguration;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RoleMapperTest {

    private Entry entry;
    private RoleConfig roleConfig;
    private RoleMapper roleMapper;

    @BeforeEach
    public void setup() throws Exception {
        roleMapper = new RoleMapper();

        entry = new DefaultEntry();
        entry.add("administrativeRole", "admins");
        entry.add("memberOf", "ou=abc,ou=area51,dc=example,dc=com", "ou=xyz,ou=area51,dc=example,dc=com");

        roleConfig = mock(RoleConfig.class);
        when(roleConfig.getName()).thenReturn("blackbird");
    }

    @Test
    public void shouldMapRolesFromAttributes() throws Exception {
        RoleConfiguration roleConfiguration = getRoleProfile("memberOf", "ou=abc,ou=area51,dc=example,dc=com", null);
        when(roleConfig.getRoleConfiguration()).thenReturn(roleConfiguration);

        Set<String> roles = roleMapper.map(entry, Collections.singletonList(roleConfig));

        assertThat(roles).containsExactlyInAnyOrder("blackbird");
    }

    @Test
    public void shouldReturnEmptyListIfNotMatchAnyRoleConfigs() throws Exception {
        RoleConfiguration roleConfiguration = getRoleProfile("memberOf", "ou=hij,ou=area51,dc=example,dc=com", null);
        when(roleConfig.getRoleConfiguration()).thenReturn(roleConfiguration);

        Set<String> roles = roleMapper.map(entry, Collections.singletonList(roleConfig));

        assertThat(true).isEqualTo(roles.isEmpty());
    }

    private RoleConfiguration getRoleProfile(String attName, String attValue, String groupFilter) {
        Map<String, String> configuration = new HashMap<>();
        configuration.put("UserGroupMembershipAttribute", attName);
        configuration.put("GroupIdentifiers", attValue);
        configuration.put("GroupMembershipFilter", groupFilter);
        return GSON.fromJson(GSON.toJson(configuration), RoleConfiguration.class);
    }
}
