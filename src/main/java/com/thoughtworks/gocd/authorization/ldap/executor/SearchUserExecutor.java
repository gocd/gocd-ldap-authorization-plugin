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
import com.thoughtworks.gocd.authorization.ldap.apacheds.Ldap;
import com.thoughtworks.gocd.authorization.ldap.apacheds.LdapFactory;
import com.thoughtworks.gocd.authorization.ldap.model.AuthConfig;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.User;
import com.thoughtworks.gocd.authorization.ldap.request.SearchUserRequest;
import com.thoughtworks.gocd.authorization.ldap.utils.Util;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.thoughtworks.gocd.authorization.ldap.LdapPlugin.LOG;

public class SearchUserExecutor implements RequestExecutor {
    private final LdapFactory ldapFactory;
    private final SearchUserRequest request;

    public SearchUserExecutor(GoPluginApiRequest request) {
        this(request, new LdapFactory());
    }

    protected SearchUserExecutor(GoPluginApiRequest request, LdapFactory ldapFactory) {
        this.request = SearchUserRequest.fromJSON(request.requestBody());
        this.ldapFactory = ldapFactory;
    }

    @Override
    public GoPluginApiResponse execute() throws Exception {
        final Set<User> users = searchUsers(request.getSearchTerm(), request.getAuthConfigs());

        return new DefaultGoPluginApiResponse(200, Util.GSON.toJson(users));
    }

    Set<User> searchUsers(String searchTerm, List<AuthConfig> authConfigs) {
        Set<User> allUsers = new HashSet<>();
        for (AuthConfig authConfig : authConfigs) {
            try {
                final LdapConfiguration configuration = authConfig.getConfiguration();
                final Ldap ldap = ldapFactory.ldapForConfiguration(configuration);
                String userSearchFilter = configuration.getUserSearchFilter();

                LOG.info("[User Search] Looking up for users matching search_term: `{}`" +
                        " using the search_filter: `{}` and auth_config: `{}`", searchTerm, userSearchFilter, authConfig.getId());

                List<User> users = ldap.search(userSearchFilter, new String[]{searchTerm}, configuration.getUserMapper(), 100);
                allUsers.addAll(users);
                if (users.size() == 100)
                    break;
            } catch (Exception e) {
                LOG.error("[User Search] Failed to search user using auth_config: `{}`", authConfig.getId(), e);
            }
        }
        return allUsers;
    }
}
