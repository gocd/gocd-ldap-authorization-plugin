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
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.authorization.ldap.LdapAuthenticator;
import com.thoughtworks.gocd.authorization.ldap.model.AuthenticationResponse;
import com.thoughtworks.gocd.authorization.ldap.request.IsValidUserRequest;

import static com.thoughtworks.go.plugin.api.response.DefaultGoApiResponse.SUCCESS_RESPONSE_CODE;
import static com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse.INTERNAL_ERROR;

public class IsValidUserExecutor implements RequestExecutor {
    private final IsValidUserRequest request;
    private final LdapAuthenticator authenticator;

    public IsValidUserExecutor(GoPluginApiRequest request, LdapAuthenticator authenticator) {
        this.request = IsValidUserRequest.fromJSON(request.requestBody());
        this.authenticator = authenticator;
    }

    @Override
    public GoPluginApiResponse execute() throws Exception {
        AuthenticationResponse authenticationResponse = authenticator.searchUserWithAuthConfig(request.getUsername(), request.getAuthConfig());

        if (authenticationResponse != null) {
            return new DefaultGoPluginApiResponse(SUCCESS_RESPONSE_CODE);
        }

        return new DefaultGoPluginApiResponse(INTERNAL_ERROR);
    }
}
