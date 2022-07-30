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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.authorization.ldap.apacheds.Ldap;
import com.thoughtworks.gocd.authorization.ldap.apacheds.LdapFactory;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;
import com.thoughtworks.gocd.authorization.ldap.validators.LdapConfigurationValidator;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

import static com.thoughtworks.gocd.authorization.ldap.LdapPlugin.LOG;

public class VerifyConnectionRequestExecutor implements RequestExecutor {
    private static final Gson GSON = new Gson();
    public static final Type PROPERTIES_TYPE = new TypeToken<Map<String, String>>() {
    }.getType();
    private final GoPluginApiRequest request;
    private final LdapConfiguration ldapConfiguration;
    private final LdapFactory ldapFactory;

    public VerifyConnectionRequestExecutor(GoPluginApiRequest request) {
        this(request, new LdapFactory());
    }

    protected VerifyConnectionRequestExecutor(GoPluginApiRequest request, LdapFactory ldapFactory) {
        this.ldapFactory = ldapFactory;
        this.request = request;
        this.ldapConfiguration = LdapConfiguration.fromJSON(request.requestBody());
    }

    @Override
    public GoPluginApiResponse execute() {
        final ValidationResult validationResult = validateAuthConfig();

        if (validationResult.hasErrors()) {
            return validationFailureResponse(validationResult);
        }

        final ValidationResult verifyConnectionResult = verifyConnection();
        if (verifyConnectionResult.hasErrors()) {
            return verifyConnectionFailureResponse(verifyConnectionResult);
        }

        return successResponse();
    }

    private ValidationResult verifyConnection() {
        final ValidationResult validationResult = new ValidationResult();
        Ldap ldap = ldapFactory.ldapForConfiguration(ldapConfiguration);

        try {
            ldap.verifyConnection();
        } catch (Exception e) {
            validationResult.addError("", e.getMessage());
            LOG.error("[Verify Connection] Verify connection failed with errors.", e);
        }
        return validationResult;
    }

    private ValidationResult validateAuthConfig() {
        final Map<String, String> properties = GSON.fromJson(request.requestBody(), PROPERTIES_TYPE);
        return new LdapConfigurationValidator().validate(properties);
    }

    private GoPluginApiResponse successResponse() {
        return responseWith("success", "Connection ok", null);
    }

    private GoPluginApiResponse verifyConnectionFailureResponse(ValidationResult validationResult) {
        return responseWith("failure", validationResult.allErrors().get(0).message(), null);
    }

    private GoPluginApiResponse validationFailureResponse(ValidationResult validationResult) {
        return responseWith("validation-failed", "Validation failed for the given Auth Config", validationResult);
    }

    private GoPluginApiResponse responseWith(String status, String message, ValidationResult validationResult) {
        final HashMap<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("message", message);

        if (validationResult != null && validationResult.hasErrors()) {
            response.put("errors", validationResult.allErrors());
        }

        return DefaultGoPluginApiResponse.success(GSON.toJson(response));
    }
}
