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

package com.thoughtworks.gocd.authorization.ldap.model;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;

public class AuthConfig {
    @Expose
    @SerializedName("id")
    private String id;

    @Expose
    @SerializedName("configuration")
    private LdapConfiguration configuration;

    public AuthConfig() {
    }

    public AuthConfig(String id, LdapConfiguration configuration) {
        this.id = id;
        this.configuration = configuration;
    }

    public String getId() {
        return id;
    }

    public LdapConfiguration getConfiguration() {
        return configuration;
    }

    public static AuthConfig fromJSON(String json) {
        return GSON.fromJson(json, AuthConfig.class);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AuthConfig that = (AuthConfig) o;

        if (id != null ? !id.equals(that.id) : that.id != null) return false;
        return configuration != null ? configuration.equals(that.configuration) : that.configuration == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (configuration != null ? configuration.hashCode() : 0);
        return result;
    }
}
