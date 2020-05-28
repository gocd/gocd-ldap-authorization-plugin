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
import com.thoughtworks.gocd.authorization.ldap.LdapAuthorizer;
import com.thoughtworks.gocd.authorization.ldap.model.AuthenticationResponse;
import com.thoughtworks.gocd.authorization.ldap.model.User;
import com.thoughtworks.gocd.authorization.ldap.request.GetUserRolesRequest;
import org.junit.Before;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import java.util.Collections;

import static com.thoughtworks.gocd.authorization.ldap.RequestBodyMother.forAuthorizeWithAttribute;
import static com.thoughtworks.gocd.authorization.ldap.RequestBodyMother.searchUserWithAuthConfig;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

public class GetUserRolesExecutorTest {

    private GoPluginApiRequest pluginRequest;
    private LdapAuthorizer ldapAuthorizer;
    private LdapAuthenticator ldapAuthenticator;

    @Before
    public void setup() {
        pluginRequest = mock(GoPluginApiRequest.class);
        ldapAuthorizer = mock(LdapAuthorizer.class);
        ldapAuthenticator = mock(LdapAuthenticator.class);
    }

    @Test
    public void shouldSearchAUser() throws Exception {
        final String requestBody = searchUserWithAuthConfig("bford", "ou=users,ou=system");
        final GetUserRolesRequest request = GetUserRolesRequest.fromJSON(requestBody);

        when(this.pluginRequest.requestBody()).thenReturn(requestBody);

        GoPluginApiResponse response = new GetUserRolesExecutor(this.pluginRequest, ldapAuthenticator, ldapAuthorizer).execute();

        verify(ldapAuthenticator).searchUserWithAuthConfig("bford", request.getAuthConfig());
        JSONAssert.assertEquals("[]", response.responseBody(), true);
    }

    @Test
    public void shouldFetchRolesAfterFindingUser() throws Exception {
        final String requestBody = forAuthorizeWithAttribute(
                "username", "some-search-bases", "admin", "ldap", null, null
        );

        final GetUserRolesRequest request = GetUserRolesRequest.fromJSON(requestBody);

        final User user = new User("username", "displayName", "mail");
        final AuthenticationResponse authenticationResponse = new AuthenticationResponse(user, request.getAuthConfig());

        when(this.pluginRequest.requestBody()).thenReturn(requestBody);
        when(ldapAuthenticator.searchUserWithAuthConfig("username", request.getAuthConfig())).thenReturn(authenticationResponse);

        new GetUserRolesExecutor(this.pluginRequest, ldapAuthenticator, ldapAuthorizer).execute();

        verify(ldapAuthorizer).authorize(user, request.getAuthConfig(), request.getRoleConfigs());
    }

    @Test
    public void executeResponse_shouldHaveUserAndRoles() throws Exception {
        final String requestBody = forAuthorizeWithAttribute(
                "username", "some-search-bases", "admin", "ldap", null, null
        );

        final GetUserRolesRequest request = GetUserRolesRequest.fromJSON(requestBody);

        final User user = new User("username", "displayName", "mail");
        final AuthenticationResponse authenticationResponse = new AuthenticationResponse(user, request.getAuthConfig());

        when(pluginRequest.requestBody()).thenReturn(requestBody);
        when(ldapAuthenticator.searchUserWithAuthConfig("username", request.getAuthConfig())).thenReturn(authenticationResponse);
        when(ldapAuthorizer.authorize(user, request.getAuthConfig(), request.getRoleConfigs())).thenReturn(Collections.singleton("admin"));

        GoPluginApiResponse response = new GetUserRolesExecutor(pluginRequest, ldapAuthenticator, ldapAuthorizer).execute();

        String expectedJSON = "[\"admin\"]";

        assertThat(response.responseCode(), is(200));

        JSONAssert.assertEquals(expectedJSON, response.responseBody(), true);
    }
}
