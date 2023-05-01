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
import com.thoughtworks.gocd.authorization.ldap.utils.Util;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class GetAuthConfigViewExecutorTest {

    @Test
    public void shouldRenderTheTemplateInJSON() throws Exception {
        GoPluginApiResponse response = new GetAuthConfigViewExecutor().execute();
        assertThat(response.responseCode()).isEqualTo(200);
        Map<String, String> hashSet = new Gson().fromJson(response.responseBody(), new TypeToken<Map<String, String>>() {
        }.getType());
        assertThat(hashSet).containsEntry("template", Util.readResource("/auth-config.template.html"));
    }

    @Test
    public void allFieldsShouldBePresentInView() throws Exception {
        String template = Util.readResource("/auth-config.template.html");
        final Document document = Jsoup.parse(template);

        final List<Configuration> metadataList = MetadataHelper.getMetadata(LdapConfiguration.class);
        for (Configuration configuration : metadataList) {
            final Elements inputFieldForKey = document.getElementsByAttributeValue("ng-model", configuration.getKey());
            assertThat(inputFieldForKey).hasSize(1);

            final Elements spanToShowError = document.getElementsByAttributeValue("ng-class", "{'is-visible': GOINPUTNAME[" + configuration.getKey() + "].$error.server}");
            assertThat(spanToShowError).hasSize(1);
            assertThat(spanToShowError.attr("ng-show")).isEqualTo("GOINPUTNAME[" + configuration.getKey() + "].$error.server");
            assertThat(spanToShowError.text()).isEqualTo("{{GOINPUTNAME[" + configuration.getKey() + "].$error.server}}");
        }

        final Elements inputs = document.select("textarea,input,select");
        assertThat(inputs).hasSize(metadataList.size());
    }
}
