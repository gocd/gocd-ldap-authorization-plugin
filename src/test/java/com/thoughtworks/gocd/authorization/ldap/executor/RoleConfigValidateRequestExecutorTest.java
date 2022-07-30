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
import org.junit.Before;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import java.util.Collections;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RoleConfigValidateRequestExecutorTest {

    private GoPluginApiRequest request;

    @Before
    public void setup() throws Exception {
        request = mock(GoPluginApiRequest.class);
    }

    @Test
    public void shouldBarfWhenUnknownKeysArePassed() throws Exception {
        when(request.requestBody()).thenReturn(new Gson().toJson(Collections.singletonMap("foo", "bar")));

        GoPluginApiResponse response = new RoleConfigValidateRequestExecutor(request).execute();
        String json = response.responseBody();

        String expectedJSON = "[\n" +
                "  {\n" +
                "    \"key\": \"foo\",\n" +
                "    \"message\": \"Is an unknown property\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"UserGroupMembershipAttribute\",\n" +
                "    \"message\": \"`UserGroupMembershipAttribute` must not be blank.\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"key\": \"GroupIdentifiers\",\n" +
                "    \"message\": \"`GroupIdentifiers` must not be blank.\"\n" +
                "  }\n" +
                "]";
        JSONAssert.assertEquals(expectedJSON, json, JSONCompareMode.NON_EXTENSIBLE);
    }

    @Test
    public void shouldErrorOutIfConfigurationIsEmpty() throws Exception {
        when(request.requestBody()).thenReturn(new Gson().toJson(Collections.emptyMap()));

        GoPluginApiResponse response = new RoleConfigValidateRequestExecutor(request).execute();
        String json = response.responseBody();

        String expectedJSON = "[\n" +
                "  {\n" +
                "  \t\"key\": \"UserGroupMembershipAttribute\",\n" +
                "    \"message\": \"`UserGroupMembershipAttribute` must not be blank.\"\n" +
                "  },\n" +
                "  {\n" +
                "  \t\"key\": \"GroupIdentifiers\",\n" +
                "    \"message\": \"`GroupIdentifiers` must not be blank.\"\n" +
                "  }\n" +
                "]";

        JSONAssert.assertEquals(expectedJSON, json, JSONCompareMode.NON_EXTENSIBLE);
    }

    @Test
    public void shouldErrorOutIfOnlyUserGroupMembershipAttributeProvided() throws Exception {
        when(request.requestBody()).thenReturn(new Gson().toJson(Collections.singletonMap("UserGroupMembershipAttribute", "MemberOf")));

        GoPluginApiResponse response = new RoleConfigValidateRequestExecutor(request).execute();
        String json = response.responseBody();

        String expectedJSON = "[\n" +
                "  {\n" +
                "  \t\"key\": \"GroupIdentifiers\",\n" +
                "    \"message\": \"`GroupIdentifiers` must not be blank.\"\n" +
                "  }\n" +
                "]";

        JSONAssert.assertEquals(expectedJSON, json, JSONCompareMode.NON_EXTENSIBLE);
    }

    @Test
    public void shouldErrorOutIfOnlyGroupIdentifiersProvided() throws Exception {
        when(request.requestBody()).thenReturn(new Gson().toJson(Collections.singletonMap("GroupIdentifiers", "ou=pune")));

        GoPluginApiResponse response = new RoleConfigValidateRequestExecutor(request).execute();
        String json = response.responseBody();

        String expectedJSON = "[\n" +
                "  {\n" +
                "  \t\"key\": \"UserGroupMembershipAttribute\",\n" +
                "    \"message\": \"`UserGroupMembershipAttribute` must not be blank.\"\n" +
                "  }\n" +
                "]";

        JSONAssert.assertEquals(expectedJSON, json, JSONCompareMode.NON_EXTENSIBLE);
    }

    @Test
    public void shouldReturnEmptyResultIfGroupMembershipFilterConfigured() throws Exception {
        when(request.requestBody()).thenReturn(new Gson().toJson(Collections.singletonMap("GroupMembershipFilter", "(| member={uid})")));

        GoPluginApiResponse response = new RoleConfigValidateRequestExecutor(request).execute();
        String json = response.responseBody();

        String expectedJSON = "[]";

        JSONAssert.assertEquals(expectedJSON, json, JSONCompareMode.NON_EXTENSIBLE);
    }
}
