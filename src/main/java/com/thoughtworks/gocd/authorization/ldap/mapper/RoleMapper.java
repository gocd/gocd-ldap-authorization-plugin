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

package com.thoughtworks.gocd.authorization.ldap.mapper;

import com.thoughtworks.gocd.authorization.ldap.model.RoleConfig;
import com.thoughtworks.gocd.authorization.ldap.model.RoleConfiguration;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;

import javax.naming.NamingException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.thoughtworks.gocd.authorization.ldap.LdapPlugin.LOG;

public class RoleMapper {
    public Set<String> map(Entry entry, List<RoleConfig> roleConfigs) {
        if (roleConfigs == null || roleConfigs.isEmpty()) {
            return Collections.emptySet();
        }

        return getUserRoles(entry, roleConfigs);
    }

    private Set<String> getUserRoles(Entry entry, List<RoleConfig> roleConfigs) {
        final Set<String> roles = new HashSet<>();

        for (RoleConfig roleConfig : roleConfigs) {
            RoleConfiguration roleConfiguration = roleConfig.getRoleConfiguration();
            if (roleConfiguration.hasGroupMembershipAttributes()) {
                LOG.debug("[Authenticate] Resolving role using role_config: `{}` and user_member_of_attribute: `{}`",
                        roleConfig.getName(), roleConfiguration.getUserGroupMembershipAttribute());
                try {
                    final Attribute memberOfAttribute = entry.get(roleConfiguration.getUserGroupMembershipAttribute());

                    if (memberOfAttribute == null) {
                        LOG.info("[Authenticate] Missing User Member of Attribute: `{}` on user entry",
                                roleConfiguration.getUserGroupMembershipAttribute());
                        continue;
                    }

                    if (hasMatchingMembershipAttribute(roleConfig, memberOfAttribute)) {
                        roles.add(roleConfig.getName());
                    }
                } catch (Exception e) {
                    LOG.error("[Authenticate] Error mapping roles using User Member of Attribute: `{}`",
                            roleConfiguration.getUserGroupMembershipAttribute(), e);
                }
            }
        }

        return roles;
    }

    private boolean hasMatchingMembershipAttribute(RoleConfig roleConfig, Attribute attribute) throws NamingException {
        final List<String> groupIdentifiers = roleConfig.getRoleConfiguration().getGroupIdentifiers();

        for (Value value : attribute) {
            if (groupIdentifiers.contains(value.getString())) {
                return true;
            }
        }

        LOG.debug("[Authenticate] Attribute {} is not part of Group Identifiers {} defined in role {}.", attribute, groupIdentifiers, roleConfig.getName());

        return false;
    }
}
