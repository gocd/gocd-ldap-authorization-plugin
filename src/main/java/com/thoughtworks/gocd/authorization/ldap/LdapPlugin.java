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

import com.thoughtworks.go.plugin.api.GoApplicationAccessor;
import com.thoughtworks.go.plugin.api.GoPlugin;
import com.thoughtworks.go.plugin.api.GoPluginIdentifier;
import com.thoughtworks.go.plugin.api.annotation.Extension;
import com.thoughtworks.go.plugin.api.annotation.Load;
import com.thoughtworks.go.plugin.api.exceptions.UnhandledRequestTypeException;
import com.thoughtworks.go.plugin.api.info.PluginContext;
import com.thoughtworks.go.plugin.api.logging.Logger;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.authorization.ldap.executor.*;
import com.thoughtworks.gocd.authorization.ldap.utils.Util;

import static com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse.INTERNAL_ERROR;

@Extension
public class LdapPlugin implements GoPlugin {
    public static final Logger LOG = Logger.getLoggerFor(LdapPlugin.class);

    private GoApplicationAccessor accessor;

    @Override
    public void initializeGoApplicationAccessor(GoApplicationAccessor accessor) {
        this.accessor = accessor;
    }

    @Load
    public void onLoad(PluginContext ctx) {
        LOG.info("Loading plugin " + Util.pluginId() + " version " + Util.fullVersion());
    }

    @Override
    public GoPluginApiResponse handle(GoPluginApiRequest request) throws UnhandledRequestTypeException {
        final ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(this.getClass().getClassLoader());
            switch (RequestFromServer.fromString(request.requestName())) {
                case REQUEST_GET_PLUGIN_ICON:
                    return new GetPluginIconExecutor().execute();
                case REQUEST_GET_CAPABILITIES:
                    return new GetCapabilitiesExecutor().execute();
                case REQUEST_GET_AUTH_CONFIG_METADATA:
                    return new GetAuthConfigMetadataExecutor().execute();
                case REQUEST_AUTH_CONFIG_VIEW:
                    return new GetAuthConfigViewExecutor().execute();
                case REQUEST_VALIDATE_AUTH_CONFIG:
                    return new AuthConfigValidateRequestExecutor(request).execute();
                case REQUEST_VERIFY_CONNECTION:
                    return new VerifyConnectionRequestExecutor(request).execute();
                case REQUEST_GET_ROLE_CONFIG_METADATA:
                    return new GetRoleConfigMetadataExecutor().execute();
                case REQUEST_ROLE_CONFIG_VIEW:
                    return new GetRoleConfigViewExecutor().execute();
                case REQUEST_VALIDATE_ROLE_CONFIG:
                    return new RoleConfigValidateRequestExecutor(request).execute();
                case REQUEST_AUTHENTICATE_USER:
                    return new UserAuthenticationExecutor(request, new LdapAuthenticator(), new LdapAuthorizer()).execute();
                case REQUEST_SEARCH_USERS:
                    return new SearchUserExecutor(request).execute();
                case REQUEST_GET_USER_ROLES:
                    return new GetUserRolesExecutor(request, new LdapAuthenticator(), new LdapAuthorizer()).execute();
                case REQUEST_IS_VALID_USER:
                    return new IsValidUserExecutor(request, new LdapAuthenticator()).execute();
                default:
                    throw new UnhandledRequestTypeException(request.requestName());
            }
        } catch (NoSuchRequestHandler e) {
            LOG.warn(e.getMessage());
            return new DefaultGoPluginApiResponse(INTERNAL_ERROR, e.getMessage());
        } catch (Exception e) {
            LOG.error("Error while executing request " + request.requestName(), e);
            return new DefaultGoPluginApiResponse(INTERNAL_ERROR, e.getMessage());
        } finally {
            Thread.currentThread().setContextClassLoader(originalClassLoader);
        }
    }

    @Override
    public GoPluginIdentifier pluginIdentifier() {
        return Constants.PLUGIN_IDENTIFIER;
    }
}
