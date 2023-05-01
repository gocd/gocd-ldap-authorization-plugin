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

package com.thoughtworks.gocd.authorization.ldap.validators;

import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationError;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class URLValidatorTest {

    @Test
    public void shouldValidateLdapUrl() throws Exception {
        final URLValidator urlValidator = new URLValidator();
        final LdapConfiguration ldapConfiguration = mock(LdapConfiguration.class);

        when(ldapConfiguration.getUrl()).thenReturn("foo");

        final ValidationResult result = urlValidator.validate(ldapConfiguration);

        assertTrue(result.hasErrors());
        assertThat(result.allErrors().get(0)).isEqualTo(new ValidationError("Url", "Invalid ldap url."));
    }

    @Test
    public void validateShouldNotHaveErrorsForAValidLdapUrl() throws Exception {
        final URLValidator urlValidator = new URLValidator();
        final LdapConfiguration ldapConfiguration = mock(LdapConfiguration.class);

        when(ldapConfiguration.getUrl()).thenReturn("ldaps://example.com:636");

        final ValidationResult result = urlValidator.validate(ldapConfiguration);

        assertFalse(result.hasErrors());
    }
}
