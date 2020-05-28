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

import com.thoughtworks.gocd.authorization.ldap.exception.InvalidUsernameException;
import com.thoughtworks.gocd.authorization.ldap.mapper.UserMapper;
import com.thoughtworks.gocd.authorization.ldap.model.User;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.any;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

public class UserMapperTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void shouldAbleToMapUserFromValidAttributes() throws Exception {
        final DefaultEntry entry = new DefaultEntry();
        entry.add("uid", "jduke");
        entry.add("displayName", "Java Duke");
        entry.add("mail", "jduke@example.com");

        UserMapper userMapper = new UserMapper("uid", "displayName", "mail");
        User user = userMapper.map(entry);

        assertThat(user, is(new User("jduke", "Java Duke", "jduke@example.com", null)));
    }

    @Test
    public void shouldBarfWhenMappingUsernameFromInvalidAttributes() throws Exception {
        final DefaultEntry entry = new DefaultEntry();
        entry.add("displayName", "Java Duke");
        final UserMapper userMapper = new UserMapper("non-exiting-field", "displayName", "mail");

        thrown.expect(any(InvalidUsernameException.class));
        thrown.expectMessage("Username can not be blank. Please check `SearchFilter` attribute on `<authConfig>` profile.");
        User user = userMapper.map(entry);

        assertNull(user);
    }
}
