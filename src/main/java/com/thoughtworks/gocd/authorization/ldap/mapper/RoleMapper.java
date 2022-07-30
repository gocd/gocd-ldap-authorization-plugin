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
import java.util.*;

import static com.thoughtworks.gocd.authorization.ldap.LdapPlugin.LOG;
import static java.text.MessageFormat.format;

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
                LOG.debug(format("[Authenticate] Resolving role using role_config: `{0}` and user_member_of_attribute: `{1}`",
                        roleConfig.getName(), roleConfiguration.getUserGroupMembershipAttribute()));
                try {
                    final Attribute memberOfAttribute = entry.get(roleConfiguration.getUserGroupMembershipAttribute());

                    if (memberOfAttribute == null) {
                        LOG.info(format("[Authenticate] Missing User Member of Attribute: `{0}` on user entry",
                                roleConfiguration.getUserGroupMembershipAttribute()));
                        continue;
                    }

                    if (hasMatchingMembershipAttribute(roleConfig, memberOfAttribute)) {
                        roles.add(roleConfig.getName());
                    }
                } catch (Exception e) {
                    LOG.error(format("[Authenticate] Error mapping roles using User Member of Attribute: `{0}`",
                            roleConfiguration.getUserGroupMembershipAttribute()), e);
                }
            }
        }

        return roles;
    }

    private boolean hasMatchingMembershipAttribute(RoleConfig roleConfig, Attribute attribute) throws NamingException {
        final List<String> groupIdentifiers = roleConfig.getRoleConfiguration().getGroupIdentifiers();

        final Iterator<Value<?>> iterator = attribute.iterator();
        while (iterator.hasNext()) {
            if (groupIdentifiers.contains(iterator.next().getString())) {
                return true;
            }
        }

        LOG.debug(format("[Authenticate] Attribute {0} is not part of Group Identifiers {1} defined in role {2}.", attribute, groupIdentifiers, roleConfig.getName()));

        return false;
    }
}
