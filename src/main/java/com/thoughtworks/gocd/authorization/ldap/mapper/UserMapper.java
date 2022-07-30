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

import com.thoughtworks.gocd.authorization.ldap.exception.LdapException;
import com.thoughtworks.gocd.authorization.ldap.model.User;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.ldap.client.template.EntryMapper;

import static com.thoughtworks.gocd.authorization.ldap.LdapPlugin.LOG;

public class UserMapper implements EntryMapper<User> {
    private final String usernameAttribute;
    private final String displayNameAttribute;
    private final String emailAttribute;

    public UserMapper(String usernameAttribute, String displayNameAttribute, String emailAttribute) {
        this.usernameAttribute = usernameAttribute;
        this.displayNameAttribute = displayNameAttribute;
        this.emailAttribute = emailAttribute;
    }

    @Override
    public User map(Entry entry) throws LdapException {
        return new User(resolveAttribute(usernameAttribute, entry),
                resolveAttribute(displayNameAttribute, entry),
                resolveAttribute(emailAttribute, entry), entry);
    }

    private String resolveAttribute(String attributeName, Entry entry) {
        try {
            return entry.containsAttribute(attributeName) ? entry.get(attributeName).getString() : null;
        } catch (LdapInvalidAttributeValueException e) {
            LOG.error("Failed to get attribute `" + attributeName + "` value.");
        }
        return null;
    }
}
