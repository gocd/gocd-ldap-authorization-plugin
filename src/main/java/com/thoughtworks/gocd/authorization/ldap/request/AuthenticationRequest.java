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

package com.thoughtworks.gocd.authorization.ldap.request;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.thoughtworks.gocd.authorization.ldap.model.AuthConfig;
import com.thoughtworks.gocd.authorization.ldap.model.Credentials;
import com.thoughtworks.gocd.authorization.ldap.model.RoleConfig;

import java.util.List;

import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;

public class AuthenticationRequest {

    @Expose
    @SerializedName("credentials")
    private Credentials credentials;

    @Expose
    @SerializedName("auth_configs")
    private List<AuthConfig> authConfigs;

    @Expose
    @SerializedName("role_configs")
    private List<RoleConfig> roleConfigs;

    public Credentials getCredentials() {
        return credentials;
    }

    public List<AuthConfig> getAuthConfigs() {
        return authConfigs;
    }

    public List<RoleConfig> getRoleConfigs() {
        return roleConfigs;
    }

    public static AuthenticationRequest fromJSON(String requestBody) {
        return GSON.fromJson(requestBody, AuthenticationRequest.class);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AuthenticationRequest that = (AuthenticationRequest) o;

        if (credentials != null ? !credentials.equals(that.credentials) : that.credentials != null) return false;
        if (authConfigs != null ? !authConfigs.equals(that.authConfigs) : that.authConfigs != null) return false;
        return roleConfigs != null ? roleConfigs.equals(that.roleConfigs) : that.roleConfigs == null;
    }

    @Override
    public int hashCode() {
        int result = credentials != null ? credentials.hashCode() : 0;
        result = 31 * result + (authConfigs != null ? authConfigs.hashCode() : 0);
        result = 31 * result + (roleConfigs != null ? roleConfigs.hashCode() : 0);
        return result;
    }
}
