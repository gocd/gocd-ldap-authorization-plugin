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

import com.thoughtworks.gocd.authorization.ldap.RequestBodyMother;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.*;;

public class RoleConfigurationTest {

    @Test
    public void shouldEncloseGroupMembershipFilterInParentheses() throws Exception {
        final RoleConfig roleConfig = RequestBodyMother.roleConfigWith("foo", "bar", "uniqueMember={0}");

        assertThat(roleConfig.getRoleConfiguration().getGroupMembershipFilter(), is("(uniqueMember={0})"));
    }
}
