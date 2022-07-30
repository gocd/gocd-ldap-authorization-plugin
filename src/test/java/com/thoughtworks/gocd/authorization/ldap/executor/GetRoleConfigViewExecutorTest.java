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
import com.thoughtworks.gocd.authorization.ldap.model.RoleConfiguration;
import com.thoughtworks.gocd.authorization.ldap.utils.Util;
import org.junit.Test;

import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.*;;

public class GetRoleConfigViewExecutorTest {

    @Test
    public void shouldRenderTheTemplateInJSON() throws Exception {
        GoPluginApiResponse response = new GetRoleConfigViewExecutor().execute();
        assertThat(response.responseCode(), is(200));
        Map<String, String> hashSet = new Gson().fromJson(response.responseBody(), new TypeToken<Map<String, String>>() {
        }.getType());
        assertThat(hashSet, hasEntry("template", Util.readResource("/role-config.template.html")));
    }

    @Test
    public void allFieldsShouldBePresentInView() throws Exception {
        String template = Util.readResource("/role-config.template.html");

        for (Configuration field : MetadataHelper.getMetadata(RoleConfiguration.class)) {
            assertThat(template, containsString("ng-model=\"" + field.getKey() + "\""));
            assertThat(template, containsString("<span class=\"form_error form-error\" ng-class=\"{'is-visible': GOINPUTNAME[" +
                    field.getKey() + "].$error.server}\" ng-show=\"GOINPUTNAME[" +
                    field.getKey() + "].$error.server\">{{GOINPUTNAME[" +
                    field.getKey() + "].$error.server}}</span>"));
        }
    }
}
