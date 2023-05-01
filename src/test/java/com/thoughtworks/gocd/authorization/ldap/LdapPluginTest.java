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

package com.thoughtworks.gocd.authorization.ldap;

import com.thoughtworks.go.plugin.api.exceptions.UnhandledRequestTypeException;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.gocd.authorization.ldap.executor.RequestFromServer;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;

import java.net.URL;
import java.net.URLClassLoader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LdapPluginTest {

    @Test
    public void shouldUsePluginClassloaderToLoadServerRequest() throws UnhandledRequestTypeException {
        final GoPluginApiRequest request = mock(GoPluginApiRequest.class);
        final LdapPlugin ldapPlugin = new LdapPlugin();
        final ClassLoader fakeClassloader = new URLClassLoader(new URL[]{});

        Thread.currentThread().setContextClassLoader(fakeClassloader);

        when(request.requestName()).then((Answer<String>) invocation -> {
            assertThat(Thread.currentThread().getContextClassLoader()).isNotEqualTo(fakeClassloader);
            return RequestFromServer.REQUEST_AUTH_CONFIG_VIEW.requestName();
        });

        assertThat(Thread.currentThread().getContextClassLoader()).isEqualTo(fakeClassloader);
        ldapPlugin.handle(request);
        assertThat(Thread.currentThread().getContextClassLoader()).isEqualTo(fakeClassloader);
    }
}
