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

import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

public class CredentialValidator implements Validatable {

    @Override
    public ValidationResult validate(final LdapConfiguration ldapConfiguration) {
        final ValidationResult validationResult = new ValidationResult();

        if (isNotBlank(ldapConfiguration.getManagerDn()) && isBlank(ldapConfiguration.getPassword())) {
            validationResult.addError("Password", "Password cannot be blank when ManagerDN is provided.");
        }

        return validationResult;
    }
}
