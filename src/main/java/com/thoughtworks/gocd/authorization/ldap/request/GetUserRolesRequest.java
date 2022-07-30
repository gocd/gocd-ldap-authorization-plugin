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
import com.thoughtworks.gocd.authorization.ldap.model.RoleConfig;

import java.util.List;

import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;

public class GetUserRolesRequest {

    @Expose
    @SerializedName("username")
    private String username;

    @Expose
    @SerializedName("auth_config")
    private AuthConfig authConfig;

    @Expose
    @SerializedName("role_configs")
    private List<RoleConfig> roleConfigs;

    public String getUsername() {
        return username;
    }

    public AuthConfig getAuthConfig() {
        return authConfig;
    }

    public List<RoleConfig> getRoleConfigs() {
        return roleConfigs;
    }


    public static GetUserRolesRequest fromJSON(String requestBody) {
        return GSON.fromJson(requestBody, GetUserRolesRequest.class);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GetUserRolesRequest that = (GetUserRolesRequest) o;

        if (username != null ? !username.equals(that.username) : that.username != null) return false;
        if (authConfig != null ? !authConfig.equals(that.authConfig) : that.authConfig != null) return false;
        return roleConfigs != null ? roleConfigs.equals(that.roleConfigs) : that.roleConfigs == null;
    }

    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (authConfig != null ? authConfig.hashCode() : 0);
        result = 31 * result + (roleConfigs != null ? roleConfigs.hashCode() : 0);
        return result;
    }
}
