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

import java.util.List;

import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;

public class SearchUserRequest {
    public static final String SEARCH_TERM = "search_term";

    @Expose
    @SerializedName(SEARCH_TERM)
    private String searchTerm;

    @Expose
    @SerializedName("auth_configs")
    private List<AuthConfig> authConfigs;

    public String getSearchTerm() {
        return searchTerm;
    }

    public List<AuthConfig> getAuthConfigs() {
        return authConfigs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SearchUserRequest that = (SearchUserRequest) o;

        if (searchTerm != null ? !searchTerm.equals(that.searchTerm) : that.searchTerm != null) return false;
        return authConfigs != null ? authConfigs.equals(that.authConfigs) : that.authConfigs == null;
    }

    @Override
    public int hashCode() {
        int result = searchTerm != null ? searchTerm.hashCode() : 0;
        result = 31 * result + (authConfigs != null ? authConfigs.hashCode() : 0);
        return result;
    }

    public static SearchUserRequest fromJSON(String requestBody) {
        return GSON.fromJson(requestBody, SearchUserRequest.class);
    }
}
