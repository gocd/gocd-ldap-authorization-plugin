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

import com.google.gson.Gson;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.authorization.ldap.LdapAuthenticator;
import com.thoughtworks.gocd.authorization.ldap.LdapAuthorizer;
import com.thoughtworks.gocd.authorization.ldap.model.AuthenticationResponse;
import com.thoughtworks.gocd.authorization.ldap.request.AuthenticationRequest;

import java.util.HashMap;
import java.util.Map;

import static com.thoughtworks.go.plugin.api.response.DefaultGoApiResponse.SUCCESS_RESPONSE_CODE;

public class UserAuthenticationExecutor implements RequestExecutor {
    private static final Gson GSON = new Gson();
    private final AuthenticationRequest request;
    private final LdapAuthenticator authenticator;
    private final LdapAuthorizer authorizer;

    public UserAuthenticationExecutor(GoPluginApiRequest request, LdapAuthenticator authenticator, LdapAuthorizer authorizer) {
        this.authenticator = authenticator;
        this.authorizer = authorizer;
        this.request = AuthenticationRequest.fromJSON(request.requestBody());
    }

    @Override
    public GoPluginApiResponse execute() throws Exception {
        AuthenticationResponse authenticationResponse = authenticator.authenticate(request.getCredentials(), request.getAuthConfigs());

        Map<String, Object> userMap = new HashMap<>();
        if (authenticationResponse != null) {
            userMap.put("user", authenticationResponse.getUser());
            userMap.put("roles", authorizer.authorize(authenticationResponse.getUser(), authenticationResponse.getConfigUsedForAuthentication(), request.getRoleConfigs()));
        }

        return new DefaultGoPluginApiResponse(SUCCESS_RESPONSE_CODE, GSON.toJson(userMap));
    }


}
