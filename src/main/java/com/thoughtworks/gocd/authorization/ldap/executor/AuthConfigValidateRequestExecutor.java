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


import com.google.gson.reflect.TypeToken;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;
import com.thoughtworks.gocd.authorization.ldap.validators.LdapConfigurationValidator;

import java.util.Map;

import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;


public class AuthConfigValidateRequestExecutor implements RequestExecutor {
    private Map<String, String> properties;

    public AuthConfigValidateRequestExecutor(GoPluginApiRequest request) {
        properties = GSON.fromJson(request.requestBody(), new TypeToken<Map<String, String>>() {
        }.getType());
    }

    public GoPluginApiResponse execute() throws Exception {
        final ValidationResult validationResult = new LdapConfigurationValidator().validate(properties);
        
        return DefaultGoPluginApiResponse.success(validationResult.toJSON());
    }
}
