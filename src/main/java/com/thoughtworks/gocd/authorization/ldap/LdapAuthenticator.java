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
import com.thoughtworks.gocd.authorization.ldap.model.*;
import org.apache.directory.api.ldap.model.entry.Entry;

import java.util.List;

import static com.thoughtworks.gocd.authorization.ldap.LdapPlugin.LOG;
import static java.text.MessageFormat.format;

public class LdapAuthenticator {

    private final LdapFactory ldapFactory;

    public LdapAuthenticator() {
        this(new LdapFactory());
    }

    protected LdapAuthenticator(LdapFactory ldapFactory) {
        this.ldapFactory = ldapFactory;
    }

    public AuthenticationResponse authenticate(Credentials credentials, List<AuthConfig> authConfigs) {
        for (AuthConfig authConfig : authConfigs) {
            AuthenticationResponse authenticationResponse = authenticateWithAuthConfig(credentials, authConfig);
            if (authenticationResponse != null)
                return authenticationResponse;
        }
        return null;
    }

    public AuthenticationResponse searchUser(String username, List<AuthConfig> authConfigs) {
        for (AuthConfig authConfig : authConfigs) {
            AuthenticationResponse authenticationResponse = searchUserWithAuthConfig(username, authConfig);
            if (authenticationResponse != null)
                return authenticationResponse;
        }
        return null;
    }

    public AuthenticationResponse searchUserWithAuthConfig(String username, AuthConfig authConfig) {
        return performWithLdap(new Credentials(username, null), authConfig, ldap -> ldap.searchUser(username, e -> e));
    }

    private AuthenticationResponse authenticateWithAuthConfig(Credentials credentials, AuthConfig authConfig) {
        return performWithLdap(credentials, authConfig, ldap -> ldap.authenticate(credentials.getUsername(), credentials.getPassword(), e -> e));
    }

    private AuthenticationResponse performWithLdap(Credentials credentials, AuthConfig authConfig, ThrowingFunction<Ldap, Entry> callback) {
        final LdapConfiguration configuration = authConfig.getConfiguration();
        final String authConfigId = authConfig.getId();
        final Ldap ldap = ldapFactory.ldapForConfiguration(configuration);

        try {
            LOG.info(format("[Authenticate] Authenticating User: {0} using auth_config: {1}", credentials.getUsername(), authConfigId));
            final Entry entry = callback.apply(ldap);
            final User user = configuration.getUserMapper().map(entry);

            return new AuthenticationResponse(user, authConfig);
        } catch (Exception e) {
            LOG.error(format("[Authenticate] Failed to authenticate user `{0}` using auth_config: {1}. ", credentials.getUsername(), authConfigId), e);
        }
        return null;
    }
}
