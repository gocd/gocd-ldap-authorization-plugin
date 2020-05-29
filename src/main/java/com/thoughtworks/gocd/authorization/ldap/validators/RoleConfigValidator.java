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

import com.thoughtworks.gocd.authorization.ldap.model.RoleConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;

import java.util.Map;

import static com.thoughtworks.gocd.authorization.ldap.model.RoleConfiguration.*;
import static java.text.MessageFormat.format;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

public class RoleConfigValidator {

    public ValidationResult validate(Map<String, String> properties) {
        final ValidationResult validationResult = RoleConfiguration.validate(properties);

        if (isNotBlank(properties.get(GROUP_MEMBERSHIP_FILTER))) {
            return validationResult;
        }

        if (isBlank(properties.get(USER_GROUP_MEMBERSHIP_ATTRIBUTE))) {
            validationResult.addError(USER_GROUP_MEMBERSHIP_ATTRIBUTE, format("`{0}` must not be blank.", USER_GROUP_MEMBERSHIP_ATTRIBUTE));
        }

        if (isBlank(properties.get(GROUP_IDENTIFIERS))) {
            validationResult.addError(GROUP_IDENTIFIERS, format("`{0}` must not be blank.", GROUP_IDENTIFIERS));
        }

        return validationResult;
    }
}