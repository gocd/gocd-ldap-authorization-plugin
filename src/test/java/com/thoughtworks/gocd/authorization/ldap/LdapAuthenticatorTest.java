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

package com.thoughtworks.gocd.authorization.ldap;

import com.thoughtworks.gocd.authorization.ldap.apacheds.Ldap;
import com.thoughtworks.gocd.authorization.ldap.apacheds.LdapFactory;
import com.thoughtworks.gocd.authorization.ldap.mapper.UserMapper;
import com.thoughtworks.gocd.authorization.ldap.model.*;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.ldap.client.template.EntryMapper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;

import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.*;;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class LdapAuthenticatorTest {

    private AuthConfig authConfig;
    private LdapFactory ldapFactory;
    private LdapConfiguration ldapConfiguration;
    private Ldap ldap;
    private Credentials credentials;
    private LdapAuthenticator ldapAuthenticator;

    @Before
    public void setUp() throws Exception {
        authConfig = mock(AuthConfig.class);
        ldapFactory = mock(LdapFactory.class);
        ldapConfiguration = mock(LdapConfiguration.class);
        ldap = mock(Ldap.class);

        credentials = new Credentials("username", "password");
        ldapAuthenticator = new LdapAuthenticator(ldapFactory);

        when(authConfig.getId()).thenReturn("id");
        when(authConfig.getConfiguration()).thenReturn(ldapConfiguration);
        when(ldapFactory.ldapForConfiguration(ldapConfiguration)).thenReturn(ldap);
    }


    @Test
    public void authenticate_shouldAuthenticateUserWithLdap() throws Exception {
        ldapAuthenticator.authenticate(credentials, Collections.singletonList(authConfig));

        verify(ldap).authenticate(eq(credentials.getUsername()), eq(credentials.getPassword()), ArgumentMatchers.<EntryMapper<Entry>>any());
    }

    @Test
    public void authenticate_shouldReturnAuthenticationResponseWithUserOnSuccessfulAuthentication() throws Exception {
        final UserMapper userMapper = mock(UserMapper.class);
        final User user = new User("jduke", "Java Duke", "jduke@example.com");
        final Entry entry = new DefaultEntry();

        when(ldap.authenticate(eq(credentials.getUsername()), eq(credentials.getPassword()), ArgumentMatchers.<EntryMapper<Entry>>any())).thenReturn(entry);
        when(ldapConfiguration.getUserMapper()).thenReturn(userMapper);
        when(userMapper.map(entry)).thenReturn(user);

        final AuthenticationResponse authenticationResponse = ldapAuthenticator.authenticate(credentials, Collections.singletonList(authConfig));

        assertThat(authenticationResponse.getUser(), is(user));
    }

    @Test
    public void authenticate_shouldReturnAuthenticationResponseWithAuthConfigOnSuccessfulAuthentication() throws Exception {
        final UserMapper userMapper = mock(UserMapper.class);
        final AuthConfig validAuthConfig = mock(AuthConfig.class);
        final LdapConfiguration validLdapConfiguration = mock(LdapConfiguration.class);
        final Entry entry = new DefaultEntry();

        when(validAuthConfig.getConfiguration()).thenReturn(validLdapConfiguration);
        when(ldapFactory.ldapForConfiguration(validAuthConfig.getConfiguration())).thenReturn(ldap);
        when(ldap.authenticate(eq(credentials.getUsername()), eq(credentials.getPassword()), ArgumentMatchers.<EntryMapper<Entry>>any())).thenThrow(new RuntimeException()).thenReturn(entry);
        when(validLdapConfiguration.getUserMapper()).thenReturn(userMapper);
        when(userMapper.map(entry)).thenReturn(mock(User.class));

        final AuthenticationResponse authenticationResponse = ldapAuthenticator.authenticate(credentials, Arrays.asList(this.authConfig, validAuthConfig));

        assertThat(authenticationResponse.getConfigUsedForAuthentication(), is(validAuthConfig));
    }

    @Test
    public void authenticate_shouldReturnAuthenticationResponseWithAuthConfigUsedForAuthenticationInCaseOfMultipleAuthConfigs() throws Exception {
        final UserMapper userMapper = mock(UserMapper.class);
        final Entry entry = new DefaultEntry();

        when(ldap.authenticate(eq(credentials.getUsername()), eq(credentials.getPassword()), ArgumentMatchers.<EntryMapper<Entry>>any())).thenReturn(entry);
        when(ldapConfiguration.getUserMapper()).thenReturn(userMapper);
        when(userMapper.map(entry)).thenReturn(mock(User.class));

        final AuthenticationResponse authenticationResponse = ldapAuthenticator.authenticate(credentials, Collections.singletonList(authConfig));

        assertThat(authenticationResponse.getConfigUsedForAuthentication(), is(authConfig));
    }

    @Test
    public void searchUser_shouldReturnAuthenticationResponseWithAuthConfigWhenUserIsFound() throws Exception {
        final String USER_NAME = "foobar";
        final UserMapper userMapper = mock(UserMapper.class);
        final AuthConfig validAuthConfig = mock(AuthConfig.class);
        final LdapConfiguration validLdapConfiguration = mock(LdapConfiguration.class);
        final Entry entry = new DefaultEntry();
        final User user = new User(USER_NAME, USER_NAME, USER_NAME + "@hmail.com");

        when(validAuthConfig.getConfiguration()).thenReturn(validLdapConfiguration);
        when(ldapFactory.ldapForConfiguration(validAuthConfig.getConfiguration())) .thenReturn(ldap);
        when(ldap.searchUser(eq(USER_NAME), ArgumentMatchers.<EntryMapper<Entry>>any())).thenReturn(entry);
        when(validLdapConfiguration.getUserMapper()).thenReturn(userMapper);
        when(userMapper.map(entry)).thenReturn(user);

        AuthenticationResponse authenticationResponse = ldapAuthenticator.searchUser(USER_NAME, Arrays.asList(this.authConfig, validAuthConfig));
        assertThat(authenticationResponse.getConfigUsedForAuthentication(), is(validAuthConfig));
    }
}
