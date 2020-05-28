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

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

public class StartTLSValidatorTest {

    @Test
    public void validateShouldEnsureStartTlsIsNotEnabledWhileUsingSSL() throws Exception {
        final LdapConfiguration configuration = new LdapConfigurationMother.Builder()
                .withURL("ldaps://localhost:389")
                .withStartTLS(true)
                .build();

        final ValidationResult validationResult = new StartTLSValidator().validate(configuration);

        assertTrue(validationResult.hasErrors());
        assertThat(validationResult.allErrors().get(0), is(new ValidationError("StartTLS", "Cannot startTLS if using `ldaps://` URL.")));
    }

    @Test
    public void shouldSkipValidationForInvalidLdapUrl() throws Exception {
        final LdapConfiguration configuration = new LdapConfigurationMother.Builder()
                .withURL("foo://localhost:389")
                .withStartTLS(true)
                .build();

        final ValidationResult validationResult = new StartTLSValidator().validate(configuration);

        assertFalse(validationResult.hasErrors());
    }

    @Test
    public void startTLSShouldBeValidForNonSSLUrl() throws Exception {
        final LdapConfiguration configuration = new LdapConfigurationMother.Builder()
                .withURL("ldap://localhost:389")
                .withStartTLS(true)
                .build();

        final ValidationResult validationResult = new StartTLSValidator().validate(configuration);

        assertFalse(validationResult.hasErrors());
    }
}
