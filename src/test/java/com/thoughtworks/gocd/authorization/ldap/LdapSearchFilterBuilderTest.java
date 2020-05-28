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

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class LdapSearchFilterBuilderTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void build_shouldEvaluateSearchExpressionAndReturnSearchFilter() throws Exception {
        final Entry entry = new DefaultEntry();
        entry.add("uid", "bford");

        final LdapSearchFilterBuilder builder = new LdapSearchFilterBuilder();
        final String filter = builder.build("member={uid}", entry);

        assertThat(filter, is("member=bford"));
    }

    @Test
    public void build_shouldEvaluateSearchExpressionWithMultipleFilterExpression() throws Exception {
        final Entry entry = new DefaultEntry();
        entry.add("uid", "bford");
        entry.setDn("cn=bford,ou=system");

        final LdapSearchFilterBuilder builder = new LdapSearchFilterBuilder();
        final String filter = builder.build("(| (member=uid={uid}) (memberUid={dn}))", entry);
        assertThat(filter, is("(| (member=uid=bford) (memberUid=cn=bford,ou=system))"));

    }

    @Test
    public void build_shouldErrorOutInAbsenceOfAttributeForAnExpression() throws Exception {
        final Entry entry = new DefaultEntry();
        entry.setDn("cn=bford,ou=system");

        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Failed to build search filter `(| (member={uid}) (memberUid=cn=bford,ou=system))`. Missing attribute for the expression `uid`");

        final LdapSearchFilterBuilder builder = new LdapSearchFilterBuilder();
        builder.build("(| (member={uid}) (memberUid={dn}))", entry);
    }
}
