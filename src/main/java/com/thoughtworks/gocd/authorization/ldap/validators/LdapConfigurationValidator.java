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
import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;

public class LdapConfigurationValidator {
    private List<Validatable> validatables = new ArrayList<>();

    public LdapConfigurationValidator() {
        validatables.add(new CredentialValidator());
        validatables.add(new CertificateValidator());
        validatables.add(new StartTLSValidator());
        validatables.add(new URLValidator());
    }

    public ValidationResult validate(Map<String, String> properties) {
        final ValidationResult validationResult = LdapConfiguration.validate(properties);
        final LdapConfiguration ldapConfiguration = LdapConfiguration.fromJSON(GSON.toJson(properties));

        validatables.forEach(validatable -> validationResult.merge(validatable.validate(ldapConfiguration)));

        return validationResult;
    }
}
