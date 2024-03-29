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
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import java.util.Collections;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthConfigValidateRequestExecutorTest {

    private GoPluginApiRequest request;

    @BeforeEach
    public void setup() throws Exception {
        request = mock(GoPluginApiRequest.class);
    }

    @Test
    public void shouldBarfWhenUnknownKeysArePassed() throws Exception {
        when(request.requestBody()).thenReturn(new Gson().toJson(Collections.singletonMap("foo", "bar")));

        GoPluginApiResponse response = new AuthConfigValidateRequestExecutor(request).execute();
        String json = response.responseBody();

        String expectedJSON = "[\n" +
                "  {\n" +
                "    \"message\": \"Url must not be blank.\",\n" +
                "    \"key\": \"Url\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"SearchBases must not be blank.\",\n" +
                "    \"key\": \"SearchBases\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"UserLoginFilter must not be blank.\",\n" +
                "    \"key\": \"UserLoginFilter\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"UserNameAttribute must not be blank.\",\n" +
                "    \"key\": \"UserNameAttribute\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"foo\",\n" +
                "    \"message\": \"Is an unknown property\"\n" +
                "  }\n" +
                "]";
        JSONAssert.assertEquals(expectedJSON, json, JSONCompareMode.NON_EXTENSIBLE);
    }

    @Test
    public void shouldValidateMandatoryKeys() throws Exception {
        when(request.requestBody()).thenReturn(new Gson().toJson(Collections.emptyMap()));

        GoPluginApiResponse response = new AuthConfigValidateRequestExecutor(request).execute();
        String json = response.responseBody();

        String expectedJSON = "[\n" +
                "  {\n" +
                "    \"message\": \"Url must not be blank.\",\n" +
                "    \"key\": \"Url\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"SearchBases must not be blank.\",\n" +
                "    \"key\": \"SearchBases\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"UserLoginFilter must not be blank.\",\n" +
                "    \"key\": \"UserLoginFilter\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"UserNameAttribute must not be blank.\",\n" +
                "    \"key\": \"UserNameAttribute\"\n" +
                "  }\n" +
                "]";
        JSONAssert.assertEquals(expectedJSON, json, JSONCompareMode.NON_EXTENSIBLE);
    }

    @Test
    public void shouldValidatePresenceOfPasswordIfManagerDNIsProvided() throws Exception {
        when(request.requestBody()).thenReturn(new Gson().toJson(Collections.singletonMap("ManagerDN", "cn=manager,ou=enterprise")));

        GoPluginApiResponse response = new AuthConfigValidateRequestExecutor(request).execute();
        String json = response.responseBody();

        String expectedJSON = "[\n" +
                "  {\n" +
                "    \"message\": \"Url must not be blank.\",\n" +
                "    \"key\": \"Url\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"SearchBases must not be blank.\",\n" +
                "    \"key\": \"SearchBases\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"UserLoginFilter must not be blank.\",\n" +
                "    \"key\": \"UserLoginFilter\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"Password cannot be blank when ManagerDN is provided.\",\n" +
                "    \"key\": \"Password\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"message\": \"UserNameAttribute must not be blank.\",\n" +
                "    \"key\": \"UserNameAttribute\"\n" +
                "  }\n" +
                "]";
        JSONAssert.assertEquals(expectedJSON, json, JSONCompareMode.NON_EXTENSIBLE);
    }
}
