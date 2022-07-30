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

package com.thoughtworks.gocd.authorization.ldap.annotation;


import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;

import java.lang.reflect.Field;
import java.util.*;

public class MetadataHelper {

    public static List<Configuration> getMetadata(Class<?> clazz) {
        return buildMetadata(clazz);
    }

    private static List<Configuration> buildMetadata(Class<?> clazz) {
        Field[] fields = clazz.getDeclaredFields();
        List<Configuration> metadata = new ArrayList<>();
        for (Field field : fields) {
            ProfileField profileField = field.getAnnotation(ProfileField.class);
            if (profileField != null) {
                final ProfileMetadata profileMetadata = new ProfileMetadata(profileField.required(), profileField.secure(), profileField.type());
                final Configuration configuration = new Configuration(profileField.key(), profileMetadata);
                metadata.add(configuration);
            }
        }
        return metadata;
    }

    public static ValidationResult validate(Class<?> clazz, Map<String, String> configuration) {
        final ValidationResult validationResult = new ValidationResult();
        final List<String> knownFields = new ArrayList<>();

        for (Configuration field : getMetadata(clazz)) {
            knownFields.add(field.getKey());
            validationResult.addError(field.validate(configuration.get(field.getKey())));
        }

        final Set<String> unknownFields = new HashSet<>(configuration.keySet());
        unknownFields.removeAll(knownFields);

        if (!unknownFields.isEmpty()) {
            for (String key : unknownFields) {
                validationResult.addError(key, "Is an unknown property");
            }
        }

        return validationResult;
    }
}
