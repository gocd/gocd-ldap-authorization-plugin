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

package com.thoughtworks.gocd.authorization.ldap.apacheds;

import com.thoughtworks.gocd.authorization.ldap.LdapConfigurationMother;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.template.EntryMapper;
import org.apache.directory.ldap.client.template.LdapConnectionTemplate;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.*;;
import static org.mockito.Mockito.*;

public class LdapTest {

    @Test
    public void shouldBeAbleToSearchUsers() throws Exception {
        final LdapConfiguration ldapConfiguration = new LdapConfigurationMother.Builder()
                .withSearchTimeout(10)
                .withSearchBases("ou=foo,dc=bar")
                .build();

        final LdapConnectionTemplate ldapConnectionTemplate = mock(LdapConnectionTemplate.class);
        final Ldap ldap = new Ldap(ldapConfiguration, ldapConnectionTemplate);
        final ArgumentCaptor<SearchRequest> argumentCaptor = ArgumentCaptor.forClass(SearchRequestImpl.class);

        when(ldapConnectionTemplate.search(argumentCaptor.capture(), ArgumentMatchers.<EntryMapper<Entry>>any())).thenReturn(Collections.singletonList(new DefaultEntry()));

        ldap.search("(uid={0})", new String[]{"foo"}, 1);

        final SearchRequest searchRequest = argumentCaptor.getValue();

        assertThat(searchRequest.getBase(), is("ou=foo,dc=bar"));
        assertThat(searchRequest.getScope(), is(SearchScope.SUBTREE));
        assertThat(searchRequest.getAttributes(), is(Collections.singletonList("*")));
        assertThat(searchRequest.getSizeLimit(), is(1L));
        assertThat(searchRequest.getFilter(), is(FilterParser.parse("(uid=foo)")));
        assertThat(searchRequest.getTimeLimit(), is(10));
    }

    @Test
    public void shouldAbleToFetchResultsFromMultipleSearchBase() throws Exception {
        final LdapConfiguration ldapConfiguration = new LdapConfigurationMother.Builder()
                .withSearchBases("ou=foo,dc=bar", "ou=baz,dc=bar")
                .build();

        final LdapConnectionTemplate ldapConnectionTemplate = mock(LdapConnectionTemplate.class);
        final Ldap ldap = new Ldap(ldapConfiguration, ldapConnectionTemplate);
        final ArgumentCaptor<SearchRequest> argumentCaptor = ArgumentCaptor.forClass(SearchRequestImpl.class);

        when(ldapConnectionTemplate.search(argumentCaptor.capture(), ArgumentMatchers.<EntryMapper<Entry>>any()))
                .thenReturn(Collections.singletonList(new DefaultEntry()))
                .thenReturn(Collections.singletonList(new DefaultEntry()));


        final List<Entry> entries = ldap.search("(uid={0})", new String[]{"foo"}, 0);

        final List<SearchRequest> searchRequests = argumentCaptor.getAllValues();

        assertThat(entries, hasSize(2));
        assertThat(searchRequests.get(0).getBase(), is("ou=foo,dc=bar"));
        assertThat(searchRequests.get(1).getBase(), is("ou=baz,dc=bar"));
    }

    @Test
    public void shouldStopSearchingIfMaxResultLimitReached() throws Exception {
        final LdapConfiguration ldapConfiguration = new LdapConfigurationMother.Builder()
                .withSearchBases("ou=foo,dc=bar", "ou=baz,dc=bar")
                .build();

        final LdapConnectionTemplate ldapConnectionTemplate = mock(LdapConnectionTemplate.class);
        final Ldap ldap = new Ldap(ldapConfiguration, ldapConnectionTemplate);
        final ArgumentCaptor<SearchRequest> argumentCaptor = ArgumentCaptor.forClass(SearchRequestImpl.class);

        when(ldapConnectionTemplate.search(argumentCaptor.capture(), ArgumentMatchers.<EntryMapper<Entry>>any()))
                .thenReturn(Arrays.asList(new DefaultEntry()));

        final List<Entry> entries = ldap.search("(uid={0})", new String[]{"foo"}, 1);

        final List<SearchRequest> searchRequests = argumentCaptor.getAllValues();

        assertThat(entries, hasSize(1));
        assertThat(searchRequests, hasSize(1));
        assertThat(searchRequests.get(0).getBase(), is("ou=foo,dc=bar"));
    }

    @Test
    public void shouldSearchGroupsBasedOnGroupMembershipFilter() throws Exception {
        final LdapConfiguration ldapConfiguration = new LdapConfigurationMother.Builder()
                .build();

        final LdapConnectionTemplate ldapConnectionTemplate = mock(LdapConnectionTemplate.class);
        final Ldap ldap = new Ldap(ldapConfiguration, ldapConnectionTemplate);
        final ArgumentCaptor<SearchRequest> argumentCaptor = ArgumentCaptor.forClass(SearchRequestImpl.class);

        when(ldapConnectionTemplate.search(argumentCaptor.capture(), ArgumentMatchers.<EntryMapper<Entry>>any())).thenReturn(Collections.singletonList(new DefaultEntry()));

        ldap.searchGroup(Arrays.asList("ou=foo,dc=bar"), "(member=admin)", entry -> entry);

        final SearchRequest searchRequest = argumentCaptor.getValue();
        assertThat(searchRequest.getBase(), is("ou=foo,dc=bar"));
        assertThat(searchRequest.getScope(), is(SearchScope.SUBTREE));
        assertThat(searchRequest.getAttributes(), is(Collections.singletonList("dn")));
        assertThat(searchRequest.getSizeLimit(), is(0L));
        assertThat(searchRequest.getFilter(), is(FilterParser.parse("(member=admin)")));
        assertThat(searchRequest.getTimeLimit(), is(5));
    }

    @Test
    public void searchGroups_shouldAbleToFetchResultsFromMultipleSearchBase() throws Exception {
        final LdapConfiguration ldapConfiguration = new LdapConfigurationMother.Builder().build();

        final LdapConnectionTemplate ldapConnectionTemplate = mock(LdapConnectionTemplate.class);
        final Ldap ldap = new Ldap(ldapConfiguration, ldapConnectionTemplate);
        final ArgumentCaptor<SearchRequest> argumentCaptor = ArgumentCaptor.forClass(SearchRequestImpl.class);

        when(ldapConnectionTemplate.search(argumentCaptor.capture(), ArgumentMatchers.<EntryMapper<Entry>>any()))
                .thenReturn(Collections.singletonList(new DefaultEntry()))
                .thenReturn(Collections.singletonList(new DefaultEntry()));


        final List<Entry> entries = ldap.searchGroup(Arrays.asList("ou=foo,dc=bar", "ou=baz,dc=bar"), "(member=admin)", entry -> entry);

        final List<SearchRequest> searchRequests = argumentCaptor.getAllValues();

        assertThat(entries, hasSize(2));
        assertThat(searchRequests.get(0).getBase(), is("ou=foo,dc=bar"));
        assertThat(searchRequests.get(1).getBase(), is("ou=baz,dc=bar"));
    }

    @Test
    public void shouldVerifyConnectionByMakingADummySearchRequest() throws Exception {
        final LdapConfiguration ldapConfiguration = new LdapConfigurationMother.Builder()
                .withSearchBases("ou=foo,dc=bar").build();

        final LdapConnectionTemplate ldapConnectionTemplate = mock(LdapConnectionTemplate.class);
        final Ldap ldap = new Ldap(ldapConfiguration, ldapConnectionTemplate);

        ldap.verifyConnection();

        verify(ldapConnectionTemplate).searchFirst(
                eq("ou=foo,dc=bar"),
                eq("(|(sAMAccountName=*test*)(uid=*test*)(cn=*test*)(mail=*test*)(otherMailbox=*test*))"),
                eq(SearchScope.SUBTREE),
                ArgumentMatchers.<EntryMapper<Entry>>any()
        );
    }
}
