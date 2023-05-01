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

package com.thoughtworks.gocd.authorization.ldap.executor;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.authorization.ldap.annotation.Configuration;
import com.thoughtworks.gocd.authorization.ldap.annotation.MetadataHelper;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GetAuthConfigMetadataExecutorTest {

    @Test
    public void shouldSerializeAllFields() throws Exception {
        GoPluginApiResponse response = new GetAuthConfigMetadataExecutor().execute();

        List<Configuration> list = new Gson().fromJson(response.responseBody(), new TypeToken<List<Configuration>>() {
        }.getType());

        assertEquals(list.size(), MetadataHelper.getMetadata(LdapConfiguration.class).size());
    }

    @Test
    public void assertJsonStructure() throws Exception {
        GoPluginApiResponse response = new GetAuthConfigMetadataExecutor().execute();

        assertThat(response.responseCode()).isEqualTo(200);
        String expectedJSON = "[\n" +
                "  {\n" +
                "    \"key\": \"Url\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": true,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"SearchBases\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": true,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"ManagerDN\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": false,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"Password\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": false,\n" +
                "      \"secure\": true\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"UserSearchFilter\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": false,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"UserLoginFilter\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": true,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"UserNameAttribute\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": true,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"DisplayNameAttribute\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": false,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"EmailAttribute\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": false,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"Certificate\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": false,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"StartTLS\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": false,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"SearchTimeout\",\n" +
                "    \"metadata\": {\n" +
                "      \"required\": false,\n" +
                "      \"secure\": false\n" +
                "    }\n" +
                "  }\n" +
                "]";

        JSONAssert.assertEquals(expectedJSON, response.responseBody(), true);
    }
}
