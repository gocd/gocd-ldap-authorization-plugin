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
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.authorization.ldap.LdapAuthenticator;
import com.thoughtworks.gocd.authorization.ldap.LdapAuthorizer;
import com.thoughtworks.gocd.authorization.ldap.model.AuthenticationResponse;
import com.thoughtworks.gocd.authorization.ldap.request.GetUserRolesRequest;

import java.util.Collections;
import java.util.Set;

import static com.thoughtworks.go.plugin.api.response.DefaultGoApiResponse.SUCCESS_RESPONSE_CODE;
import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;

public class GetUserRolesExecutor implements RequestExecutor {
    private final GetUserRolesRequest request;
    private final LdapAuthenticator authenticator;
    private final LdapAuthorizer authorizer;

    public GetUserRolesExecutor(GoPluginApiRequest request, LdapAuthenticator authenticator, LdapAuthorizer authorizer) {
        this.request = GetUserRolesRequest.fromJSON(request.requestBody());
        this.authenticator = authenticator;
        this.authorizer = authorizer;
    }

    @Override
    public GoPluginApiResponse execute() throws Exception {
        AuthenticationResponse authenticationResponse = authenticator.searchUserWithAuthConfig(request.getUsername(), request.getAuthConfig());

        Set<String> userRoles = Collections.emptySet();
        if (authenticationResponse != null) {
            userRoles = authorizer.authorize(authenticationResponse.getUser(), authenticationResponse.getConfigUsedForAuthentication(), request.getRoleConfigs());
        }

        return new DefaultGoPluginApiResponse(SUCCESS_RESPONSE_CODE, GSON.toJson(userRoles));
    }
}
