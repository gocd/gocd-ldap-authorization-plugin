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

package com.thoughtworks.gocd.authorization.ldap;

import com.thoughtworks.gocd.authorization.ldap.apacheds.Ldap;
import com.thoughtworks.gocd.authorization.ldap.apacheds.LdapFactory;
import com.thoughtworks.gocd.authorization.ldap.mapper.RoleMapper;
import com.thoughtworks.gocd.authorization.ldap.model.AuthConfig;
import com.thoughtworks.gocd.authorization.ldap.model.RoleConfig;
import com.thoughtworks.gocd.authorization.ldap.model.RoleConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.User;
import org.apache.directory.api.ldap.model.entry.Entry;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.thoughtworks.gocd.authorization.ldap.LdapPlugin.LOG;

public class LdapAuthorizer {
    private final LdapFactory ldapFactory;
    private final RoleMapper roleMapper;
    private final LdapSearchFilterBuilder builder;

    public LdapAuthorizer() {
        this(new LdapFactory(), new RoleMapper(), new LdapSearchFilterBuilder());
    }

    protected LdapAuthorizer(LdapFactory ldapFactory, RoleMapper roleMapper, LdapSearchFilterBuilder builder) {
        this.ldapFactory = ldapFactory;
        this.roleMapper = roleMapper;
        this.builder = builder;
    }

    public Set<String> authorize(User user, AuthConfig authConfig, List<RoleConfig> roleConfigs) {
        final List<RoleConfig> roles = filterRoles(authConfig, roleConfigs);

        if (roles.isEmpty()) {
            LOG.info("[Authenticate] Skipping authorization for user: `{}` as no roles defined for auth_config: `{}`",
                    user.getUsername(), authConfig.getId());
            return Collections.emptySet();
        }

        return authorizeUser(user, authConfig, roles);
    }


    private List<RoleConfig> filterRoles(AuthConfig authConfig, List<RoleConfig> roleConfigs) {
        if (roleConfigs == null) {
            return Collections.emptyList();
        }

        return roleConfigs.stream().filter(roleConfig -> isValidRoleConfig(authConfig, roleConfig))
                .collect(Collectors.toList());
    }

    private boolean isValidRoleConfig(AuthConfig authConfig, RoleConfig roleConfig) {
        if (!roleConfig.getAuthConfigId().equals(authConfig.getId())) {
            return false;
        }

        boolean isValidRole = roleConfig.getRoleConfiguration().hasGroupMembershipAttributes() ||
                roleConfig.getRoleConfiguration().hasGroupMembershipFilter();

        if (!isValidRole) {
            LOG.warn("[Authenticate] Skipping authorization mapping for plugin role config: `{}` as it is invalid.", roleConfig.getName());
        }

        return isValidRole;
    }

    private List<RoleConfig> unMappedRoles(Set<String> roles, List<RoleConfig> roleConfigs) {
        return roleConfigs.stream().filter(roleConfig -> !roles.contains(roleConfig.getName())).collect(Collectors.toList());
    }

    private Set<String> authorizeUser(User user, AuthConfig authConfig, List<RoleConfig> roleConfigs) {
        try {
            LOG.debug("[Authenticate] Resolving roles for user: `{}` using auth_config: `{}`.", user.getUsername(), authConfig.getId());
            final Set<String> roles = getRolesBasedOnUserAttributeMapping(user, roleConfigs);
            roles.addAll(getRolesBasedOnGroupMembershipFilter(user, authConfig, unMappedRoles(roles, roleConfigs)));

            return roles;
        } catch (Exception e) {
            LOG.error("[Authenticate] Error resolving roles for user: `{}` using auth_config: `{}`", user.getUsername(), authConfig.getId(), e);
        }
        return Collections.emptySet();
    }

    private Set<String> getRolesBasedOnGroupMembershipFilter(User user, AuthConfig authConfig, List<RoleConfig> roleConfigs) {
        LOG.debug("[Authenticate] Resolving roles using user group membership filter.");
        final Ldap ldap = ldapFactory.ldapForConfiguration(authConfig.getConfiguration());

        Set<String> userRoles = new HashSet<>();
        for (RoleConfig roleConfig : roleConfigs) {
            RoleConfiguration roleConfiguration = roleConfig.getRoleConfiguration();
            if (!roleConfiguration.hasGroupMembershipFilter()) {
                continue;
            }

            try {
                LOG.debug("[Authenticate] Resolving role using role_config: `{}` and group_membership_filter: `{}`",
                        roleConfig.getName(), roleConfiguration.getGroupMembershipFilter());
                final String filter = builder.build(roleConfiguration.getGroupMembershipFilter(), user.getEntry());
                final List<Entry> entries = ldap.searchGroup(roleConfiguration.getGroupSearchBases(), filter, e -> e);
                if (!entries.isEmpty()) {
                    userRoles.add(roleConfig.getName());
                }
            } catch (Exception e) {
                LOG.error("[Authenticate] Error assigning role: `{}` using group membership filter: `{}`.", roleConfig.getName(), roleConfiguration.getGroupMembershipFilter(), e);
            }
        }
        if (userRoles.isEmpty()) {
            LOG.debug("[Authenticate] No roles found using user group membership filter.");
        }
        return userRoles;
    }

    private Set<String> getRolesBasedOnUserAttributeMapping(User user, List<RoleConfig> roleConfigs) {
        LOG.debug("[Authenticate] Resolving roles using user group membership attribute.");
        Set<String> roles = roleMapper.map(user.getEntry(), roleConfigs);
        if (roles.isEmpty()) {
            LOG.debug("[Authenticate] No roles found using user group membership attribute.");
        }
        return roles;
    }
}
