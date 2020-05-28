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

package com.thoughtworks.gocd.authorization.ldap.request;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.thoughtworks.gocd.authorization.ldap.model.AuthConfig;

import java.util.Objects;

import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;

public class IsValidUserRequest {

    @Expose
    @SerializedName("username")
    private String username;

    @Expose
    @SerializedName("auth_config")
    private AuthConfig authConfig;

    public String getUsername() {
        return username;
    }

    public AuthConfig getAuthConfig() {
        return authConfig;
    }

    public static IsValidUserRequest fromJSON(String requestBody) {
        return GSON.fromJson(requestBody, IsValidUserRequest.class);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IsValidUserRequest that = (IsValidUserRequest) o;
        return Objects.equals(username, that.username) &&
                Objects.equals(authConfig, that.authConfig);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, authConfig);
    }
}
