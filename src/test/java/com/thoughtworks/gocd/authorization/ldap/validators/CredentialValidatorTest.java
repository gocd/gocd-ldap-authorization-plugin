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

package com.thoughtworks.gocd.authorization.ldap.validators;

import com.thoughtworks.gocd.authorization.ldap.LdapConfigurationMother;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationError;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;
import org.junit.Test;

import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

public class CredentialValidatorTest {

    @Test
    public void shouldReturnValidationResultWithoutErrorWhenManagerDnAndPasswordProvided() throws Exception {
        final LdapConfiguration configuration = new LdapConfigurationMother.Builder()
                .withManagerDN("uid=admin,ou=system")
                .withPassword("secret")
                .build();

        final ValidationResult result = new CredentialValidator().validate(configuration);

        assertFalse(result.hasErrors());
    }

    @Test
    public void shouldReturnValidationResultWithErrorWhenOnlyManagerDnIsProvided() throws Exception {
        final LdapConfiguration configuration = new LdapConfigurationMother.Builder()
                .withManagerDN("uid=admin,ou=system")
                .withPassword(null)
                .build();

        final ValidationResult result = new CredentialValidator().validate(configuration);

        assertTrue(result.hasErrors());
        assertThat(result.allErrors(), hasSize(1));

        final ValidationError validationError = result.allErrors().get(0);
        assertThat(validationError.key(), is("Password"));
        assertThat(validationError.message(), is("Password cannot be blank when ManagerDN is provided."));
    }
}
