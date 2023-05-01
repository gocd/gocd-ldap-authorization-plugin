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

package com.thoughtworks.gocd.authorization.ldap.executor;

import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.authorization.ldap.LdapAuthenticator;
import com.thoughtworks.gocd.authorization.ldap.LdapAuthorizer;
import com.thoughtworks.gocd.authorization.ldap.model.AuthConfig;
import com.thoughtworks.gocd.authorization.ldap.model.AuthenticationResponse;
import com.thoughtworks.gocd.authorization.ldap.model.Credentials;
import com.thoughtworks.gocd.authorization.ldap.model.User;
import com.thoughtworks.gocd.authorization.ldap.request.AuthenticationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.skyscreamer.jsonassert.JSONAssert;

import java.util.Collections;
import java.util.List;

import static com.thoughtworks.gocd.authorization.ldap.RequestBodyMother.forAuthenticate;
import static com.thoughtworks.gocd.authorization.ldap.RequestBodyMother.forAuthorizeWithAttribute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class UserAuthenticationExecutorTest {
    private GoPluginApiRequest request;
    private LdapAuthorizer ldapAuthorizer;
    private LdapAuthenticator ldapAuthenticator;

    @BeforeEach
    public void setup() {
        request = mock(GoPluginApiRequest.class);
        ldapAuthorizer = mock(LdapAuthorizer.class);
        ldapAuthenticator = mock(LdapAuthenticator.class);
    }

    @Test
    public void shouldAuthenticateAUser() throws Exception {
        final String requestBody = forAuthenticate("bford", "bob", "ou=users,ou=system");
        final AuthenticationRequest authenticationRequest = AuthenticationRequest.fromJSON(requestBody);
        when(request.requestBody()).thenReturn(requestBody);

        new UserAuthenticationExecutor(request, ldapAuthenticator, ldapAuthorizer).execute();

        verify(ldapAuthenticator).authenticate(new Credentials("bford", "bob"), authenticationRequest.getAuthConfigs());
    }

    @Test
    public void shouldFetchRolesPostAuthentication() throws Exception {
        final String requestBody = forAuthorizeWithAttribute(
                "username", "password", "some-search-bases", "admin", "ldap", null, null
        );

        final AuthenticationRequest authenticationRequest = AuthenticationRequest.fromJSON(requestBody);

        final User user = new User("username", "displayName", "mail");
        final AuthenticationResponse authenticationResponse = new AuthenticationResponse(user, authenticationRequest.getAuthConfigs().get(0));

        when(request.requestBody()).thenReturn(requestBody);
        when(ldapAuthenticator.authenticate(any(Credentials.class), ArgumentMatchers.<List<AuthConfig>>any())).thenReturn(authenticationResponse);

        new UserAuthenticationExecutor(request, ldapAuthenticator, ldapAuthorizer).execute();

        verify(ldapAuthorizer).authorize(user, authenticationRequest.getAuthConfigs().get(0), authenticationRequest.getRoleConfigs());
    }

    @Test
    public void executeResponse_shouldHaveUserAndRoles() throws Exception {
        final String requestBody = forAuthorizeWithAttribute(
                "username", "password", "some-search-bases", "admin", "ldap", null, null
        );

        final AuthenticationRequest authenticationRequest = AuthenticationRequest.fromJSON(requestBody);

        final User user = new User("username", "displayName", "mail");
        final AuthenticationResponse authenticationResponse = new AuthenticationResponse(user, authenticationRequest.getAuthConfigs().get(0));

        when(request.requestBody()).thenReturn(requestBody);
        when(ldapAuthenticator.authenticate(any(Credentials.class), ArgumentMatchers.<List<AuthConfig>>any())).thenReturn(authenticationResponse);
        when(ldapAuthorizer.authorize(user, authenticationRequest.getAuthConfigs().get(0), authenticationRequest.getRoleConfigs())).thenReturn(Collections.singleton("admin"));

        final GoPluginApiResponse response = new UserAuthenticationExecutor(request, ldapAuthenticator, ldapAuthorizer).execute();

        String expectedJSON = "{\n" +
                "  \"roles\": [\"admin\"],\n" +
                "  \"user\": {\n" +
                "    \"username\": \"username\",\n" +
                "    \"display_name\": \"displayName\",\n" +
                "    \"email\": \"mail\"\n" +
                "  }\n" +
                "}";

        assertThat(response.responseCode()).isEqualTo(200);

        JSONAssert.assertEquals(expectedJSON, response.responseBody(), true);
    }
}
