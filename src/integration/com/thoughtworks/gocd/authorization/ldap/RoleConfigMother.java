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

package com.thoughtworks.gocd.authorization.ldap;

import com.google.gson.Gson;
import com.thoughtworks.gocd.authorization.ldap.model.RoleConfig;

import java.util.HashMap;
import java.util.Map;

public class RoleConfigMother {

    private static RoleConfig roleConfig(String roleName, String authConfigId, String attributeName, String attributeValue, String groupMembershipFilter, String groupMembershipSearchBase) {

        Map<String, Object> roleConfig = new HashMap<>();
        roleConfig.put("name", roleName);
        roleConfig.put("auth_config_id", authConfigId);

        Map<String, String> configuration = new HashMap<>();
        configuration.put("UserGroupMembershipAttribute", attributeName);
        configuration.put("GroupIdentifiers", attributeValue);
        configuration.put("GroupMembershipFilter", groupMembershipFilter);
        configuration.put("GroupSearchBases", groupMembershipSearchBase);

        roleConfig.put("configuration", configuration);

        return RoleConfig.fromJSON(new Gson().toJson(roleConfig));
    }

    public static RoleConfig roleConfigWithAttribute(String roleName, String authConfigId, String attributeName, String attributeValue) {
        return roleConfig(roleName, authConfigId, attributeName, attributeValue, null, null);
    }

    public static RoleConfig roleConfigWithGroupMembershipFilter(String roleName, String authConfigId, String groupMembershipFilter, String groupMembershipSearchBase) {
        return roleConfig(roleName, authConfigId, null, null, groupMembershipFilter, groupMembershipSearchBase);
    }

}
