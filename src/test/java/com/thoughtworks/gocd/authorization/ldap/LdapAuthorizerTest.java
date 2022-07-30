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

import com.thoughtworks.gocd.authorization.ldap.apacheds.Ldap;
import com.thoughtworks.gocd.authorization.ldap.apacheds.LdapFactory;
import com.thoughtworks.gocd.authorization.ldap.mapper.RoleMapper;
import com.thoughtworks.gocd.authorization.ldap.model.AuthConfig;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.RoleConfig;
import com.thoughtworks.gocd.authorization.ldap.model.User;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.ldap.client.template.EntryMapper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Captor;
import org.mockito.Mock;

import javax.naming.NamingException;
import javax.naming.directory.BasicAttributes;
import java.util.*;

import static com.thoughtworks.gocd.authorization.ldap.RequestBodyMother.roleConfigWith;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.*;;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;

public class LdapAuthorizerTest {

    @Mock
    private Entry entry;
    @Mock
    private LdapFactory ldapFactory;
    @Mock
    private RoleMapper roleMapper;
    @Mock
    private Ldap ldap;
    @Mock
    private LdapSearchFilterBuilder builder;
    @Captor
    private ArgumentCaptor<List<RoleConfig>> roleConfigArgumentCaptor;

    private User user;
    private LdapAuthorizer ldapAuthorizer;

    @Before
    public void setUp() throws Exception {
        openMocks(this);
        user = new User("ford", "bford", "ford@aspire.com", entry);

        ldapAuthorizer = new LdapAuthorizer(ldapFactory, roleMapper, builder);

        when(ldapFactory.ldapForConfiguration(ArgumentMatchers.any(LdapConfiguration.class))).thenReturn(ldap);
    }

    @Test
    public void authorize_shouldFetchRolesFromUserAttributes() throws Exception {
        AuthConfig authConfig = RequestBodyMother.authConfigWith("ldap_server_east");
        RoleConfig admin = roleConfigWith("admin", "ldap_server_east");
        RoleConfig view = roleConfigWith("view", "ldap_server_west");

        when(roleMapper.map(eq(entry), roleConfigArgumentCaptor.capture())).thenReturn(Collections.singleton("admin"));

        final Set<String> roles = ldapAuthorizer.authorize(user, authConfig, Arrays.asList(admin, view));

        assertThat(roleConfigArgumentCaptor.getValue(), contains(admin));
        assertThat(roleConfigArgumentCaptor.getValue().size(), is(1));
        assertThat(roles.size(), is(1));
        assertThat(roles, contains("admin"));
    }

    @Test
    public void authorize_shouldReturnEmptySetIfRoleConfigsIsEmpty() throws Exception {
        AuthConfig authConfig = RequestBodyMother.authConfigWith("ldap_server_east");

        final Set<String> roles = ldapAuthorizer.authorize(user, authConfig, Collections.emptyList());

        assertThat(roles, hasSize(0));
        verifyNoMoreInteractions(roleMapper);
        verifyNoMoreInteractions(ldapFactory);
    }

    @Test
    public void authorize_shouldMapRolesBasedOnGroupMembership() throws NamingException {
        final AuthConfig authConfig = RequestBodyMother.authConfigWith("ldap_server_east");
        final String groupMembershipExpression = "(| (member={uid}) (memberUid={dn}))";
        final String groupMembershipFilter = "(| (member=uid=admin) (memberUid=dn=something))";
        final List<String> groupMembershipSearchBase = Arrays.asList("ou=foo");
        final RoleConfig roleConfig = roleConfigWith("admin", "ldap_server_east", groupMembershipExpression, "ou=foo");

        when(builder.build(groupMembershipExpression, entry)).thenReturn(groupMembershipFilter);
        when(ldapFactory.ldapForConfiguration(authConfig.getConfiguration())).thenReturn(ldap);
        when(ldap.searchGroup(eq(groupMembershipSearchBase), eq(groupMembershipFilter), ArgumentMatchers.<EntryMapper<Entry>>any())).thenReturn(Arrays.asList(new DefaultEntry()));

        final Set<String> roles = ldapAuthorizer.authorize(user, authConfig, Arrays.asList(roleConfig));

        assertThat(roles, hasSize(1));
        assertThat(roles, contains("admin"));
    }

    @Test
    public void authorize_shouldMapRolesBasedOnGroupMembershipForAllTheRoleConfigsProvided() throws Exception {
        final AuthConfig authConfig = RequestBodyMother.authConfigWith("ldap_server_east");
        final String memberExpression = "(member={uid})";
        final String memberUidExpression = "(memberUid={dn})";
        final RoleConfig admin = roleConfigWith("admin", "ldap_server_east", memberExpression);

        final String memberFilter = "(member=uid=admin)";
        final String memberUidFilter = "(memberUid=dn=something)";
        final RoleConfig view = roleConfigWith("view", "ldap_server_east", memberUidExpression);

        when(builder.build(memberExpression, entry)).thenReturn(memberFilter);
        when(builder.build(memberUidExpression, entry)).thenReturn(memberUidFilter);
        when(ldapFactory.ldapForConfiguration(authConfig.getConfiguration())).thenReturn(ldap);
        when(ldap.searchGroup(eq(new ArrayList<>()), eq(memberFilter), ArgumentMatchers.<EntryMapper<BasicAttributes>>any())).thenReturn(Arrays.asList(new BasicAttributes()));
        when(ldap.searchGroup(eq(new ArrayList<>()), eq(memberUidFilter), ArgumentMatchers.<EntryMapper<BasicAttributes>>any())).thenReturn(Arrays.asList(new BasicAttributes()));

        final Set<String> roles = ldapAuthorizer.authorize(user, authConfig, Arrays.asList(admin, view));

        assertThat(roles, hasSize(2));
        assertThat(roles, containsInAnyOrder("admin", "view"));
    }

    @Test
    public void authorize_shouldIgnoreMappingGroupMembershipIfUserAttributeResolvesTheRole() throws Exception {
        AuthConfig authConfig = RequestBodyMother.authConfigWith("ldap_server_east");
        RoleConfig admin = roleConfigWith("admin", "ldap_server_east");

        when(roleMapper.map(eq(entry), roleConfigArgumentCaptor.capture())).thenReturn(Collections.singleton("admin"));

        final Set<String> roles = ldapAuthorizer.authorize(user, authConfig, Arrays.asList(admin));

        assertThat(roleConfigArgumentCaptor.getValue(), contains(admin));
        assertThat(roleConfigArgumentCaptor.getValue().size(), is(1));
        assertThat(roles.size(), is(1));
        assertThat(roles, contains("admin"));

        verifyNoMoreInteractions(ldap);
        verifyNoMoreInteractions(builder);
    }
}
