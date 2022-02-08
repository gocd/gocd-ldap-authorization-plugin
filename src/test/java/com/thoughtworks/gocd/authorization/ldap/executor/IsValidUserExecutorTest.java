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

package com.thoughtworks.gocd.authorization.ldap.executor;

import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.authorization.ldap.LdapAuthenticator;
import com.thoughtworks.gocd.authorization.ldap.model.AuthenticationResponse;
import com.thoughtworks.gocd.authorization.ldap.model.User;
import com.thoughtworks.gocd.authorization.ldap.request.IsValidUserRequest;
import org.junit.Before;
import org.junit.Test;

import static com.thoughtworks.gocd.authorization.ldap.RequestBodyMother.getRequestBodyMapForIsUserValid;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.*;;
import static org.mockito.Mockito.*;

public class IsValidUserExecutorTest {

    private GoPluginApiRequest pluginRequest;
    private LdapAuthenticator ldapAuthenticator;

    @Before
    public void setup() {
        pluginRequest = mock(GoPluginApiRequest.class);
        ldapAuthenticator = mock(LdapAuthenticator.class);
    }

    @Test
    public void shouldAskLdapAuthenticatorToSearchAUser() throws Exception {
        final String requestBody = getRequestBodyMapForIsUserValid("bford", "config1", "ou=users,ou=system");
        final IsValidUserRequest request = IsValidUserRequest.fromJSON(requestBody);

        when(this.pluginRequest.requestBody()).thenReturn(requestBody);

        new IsValidUserExecutor(this.pluginRequest, ldapAuthenticator).execute();

        verify(ldapAuthenticator).searchUserWithAuthConfig("bford", request.getAuthConfig());
    }

    @Test
    public void shouldReturn200InCaseAuthenticatorFindsTheUser() throws Exception {
        final String requestBody = getRequestBodyMapForIsUserValid("bford", "config1", "ou=users,ou=system");
        final IsValidUserRequest request = IsValidUserRequest.fromJSON(requestBody);

        when(this.pluginRequest.requestBody()).thenReturn(requestBody);
        final User user = new User("bford", "displayName", "mail");
        when(ldapAuthenticator.searchUserWithAuthConfig("bford", request.getAuthConfig())).thenReturn(new AuthenticationResponse(user, request.getAuthConfig()));

        GoPluginApiResponse response = new IsValidUserExecutor(this.pluginRequest, ldapAuthenticator).execute();

        assertThat(response.responseCode(), is(200));
        verify(ldapAuthenticator).searchUserWithAuthConfig("bford", request.getAuthConfig());
    }

    @Test
    public void shouldReturnNon200InCaseAuthenticatorFindsTheUser() throws Exception {
        final String requestBody = getRequestBodyMapForIsUserValid("bford", "config1", "ou=users,ou=system");
        final IsValidUserRequest request = IsValidUserRequest.fromJSON(requestBody);

        when(this.pluginRequest.requestBody()).thenReturn(requestBody);
        when(ldapAuthenticator.searchUserWithAuthConfig("bford", request.getAuthConfig())).thenReturn(null);

        GoPluginApiResponse response = new IsValidUserExecutor(this.pluginRequest, ldapAuthenticator).execute();

        assertThat(response.responseCode(), is(500));
        verify(ldapAuthenticator).searchUserWithAuthConfig("bford", request.getAuthConfig());
    }
}
