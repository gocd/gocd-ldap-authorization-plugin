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

package com.thoughtworks.gocd.authorization.ldap.model;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.thoughtworks.gocd.authorization.ldap.annotation.MetadataHelper;
import com.thoughtworks.gocd.authorization.ldap.annotation.ProfileField;
import com.thoughtworks.gocd.authorization.ldap.mapper.UserMapper;
import com.thoughtworks.gocd.authorization.ldap.utils.Util;
import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.exception.LdapURLEncodingException;
import org.apache.directory.api.ldap.model.url.LdapUrl;

import java.util.List;
import java.util.Map;

import static com.thoughtworks.gocd.authorization.ldap.LdapPlugin.LOG;
import static com.thoughtworks.gocd.authorization.ldap.utils.Util.GSON;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.trimToNull;

public class LdapConfiguration {
    private static final String DEFAULT_USER_SEARCH_FILTER = "(|(sAMAccountName=*{0}*)(uid=*{0}*)(cn=*{0}*)(mail=*{0}*)(otherMailbox=*{0}*))";

    @Expose
    @SerializedName("Url")
    @ProfileField(key = "Url", required = true, secure = false)
    private String ldapUrl;

    @Expose
    @SerializedName("SearchBases")
    @ProfileField(key = "SearchBases", required = true, secure = false)
    private String searchBases;

    @Expose
    @SerializedName("ManagerDN")
    @ProfileField(key = "ManagerDN", required = false, secure = false)
    private String managerDn;

    @Expose
    @SerializedName("Password")
    @ProfileField(key = "Password", required = false, secure = true)
    private String password;

    @Expose
    @SerializedName("UserSearchFilter")
    @ProfileField(key = "UserSearchFilter", required = false, secure = false)
    private String userSearchFilter;

    @Expose
    @SerializedName("UserLoginFilter")
    @ProfileField(key = "UserLoginFilter", required = true, secure = false)
    private String userLoginFilter;

    @Expose
    @SerializedName("UserNameAttribute")
    @ProfileField(key = "UserNameAttribute", required = true, secure = false)
    private String userNameAttribute;

    @Expose
    @SerializedName("DisplayNameAttribute")
    @ProfileField(key = "DisplayNameAttribute", required = false, secure = false)
    private String displayNameAttribute;

    @Expose
    @SerializedName("EmailAttribute")
    @ProfileField(key = "EmailAttribute", required = false, secure = false)
    private String emailAttribute;

    @Expose
    @SerializedName("Certificate")
    @ProfileField(key = "Certificate", required = false, secure = false)
    private String certificate;

    @Expose
    @SerializedName("StartTLS")
    @ProfileField(key = "StartTLS", required = false, secure = false)
    private boolean startTLS = false;

    @Expose
    @SerializedName("SearchTimeout")
    @ProfileField(key = "SearchTimeout", required = false, secure = false)
    private String searchTimeout = "5";

    public static LdapConfiguration fromJSON(String json) {
        return GSON.fromJson(json, LdapConfiguration.class);
    }

    public String getUrl() {
        return this.ldapUrl;
    }

    public LdapUrl getLdapUrl() {
        try {
            return new LdapUrl(ldapUrl);
        } catch (Exception e) {
            LOG.error("Error while parsing url", e);
        }
        return null;
    }

    public boolean useSSL() {
        return LdapUrl.LDAPS_SCHEME.equalsIgnoreCase(getLdapUrl().getScheme());
    }

    public List<String> getSearchBases() {
        return Util.splitIntoLinesAndTrimSpaces(searchBases);
    }

    public String getManagerDn() {
        return managerDn;
    }

    public String getPassword() {
        return password;
    }

    public String getUserLoginFilter() {
        return Util.encloseParentheses(userLoginFilter);
    }

    public String getUserSearchFilter() {
        return Util.encloseParentheses(isBlank(this.userSearchFilter) ? DEFAULT_USER_SEARCH_FILTER : this.userSearchFilter);
    }

    public String getUserNameAttribute() {
        return userNameAttribute;
    }

    public String getDisplayNameAttribute() {
        return isBlank(this.displayNameAttribute) ? "cn" : this.displayNameAttribute;
    }

    public String getEmailAttribute() {
        return isBlank(emailAttribute) ? "mail" : emailAttribute;
    }

    public UserMapper getUserMapper() {
        return new UserMapper(getUserNameAttribute(), getDisplayNameAttribute(), getEmailAttribute());
    }

    public static ValidationResult validate(Map<String, String> properties) {
        return MetadataHelper.validate(LdapConfiguration.class, properties);
    }

    public String getCertificate() {
        return trimToNull(this.certificate);
    }

    public boolean startTLS() {
        return startTLS;
    }

    public int getSearchTimeout() {
        final String timeout = StringUtils.stripToEmpty(searchTimeout);
        if (StringUtils.isBlank(timeout)) {
            return 5;
        }
        return Integer.parseInt(timeout);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        LdapConfiguration that = (LdapConfiguration) o;

        if (startTLS != that.startTLS) return false;
        if (ldapUrl != null ? !ldapUrl.equals(that.ldapUrl) : that.ldapUrl != null) return false;
        if (searchBases != null ? !searchBases.equals(that.searchBases) : that.searchBases != null) return false;
        if (managerDn != null ? !managerDn.equals(that.managerDn) : that.managerDn != null) return false;
        if (password != null ? !password.equals(that.password) : that.password != null) return false;
        if (userSearchFilter != null ? !userSearchFilter.equals(that.userSearchFilter) : that.userSearchFilter != null)
            return false;
        if (userLoginFilter != null ? !userLoginFilter.equals(that.userLoginFilter) : that.userLoginFilter != null)
            return false;
        if (userNameAttribute != null ? !userNameAttribute.equals(that.userNameAttribute) : that.userNameAttribute != null)
            return false;
        if (displayNameAttribute != null ? !displayNameAttribute.equals(that.displayNameAttribute) : that.displayNameAttribute != null)
            return false;
        if (emailAttribute != null ? !emailAttribute.equals(that.emailAttribute) : that.emailAttribute != null)
            return false;
        if (certificate != null ? !certificate.equals(that.certificate) : that.certificate != null) return false;
        return searchTimeout != null ? searchTimeout.equals(that.searchTimeout) : that.searchTimeout == null;
    }

    @Override
    public int hashCode() {
        int result = ldapUrl != null ? ldapUrl.hashCode() : 0;
        result = 31 * result + (searchBases != null ? searchBases.hashCode() : 0);
        result = 31 * result + (managerDn != null ? managerDn.hashCode() : 0);
        result = 31 * result + (password != null ? password.hashCode() : 0);
        result = 31 * result + (userSearchFilter != null ? userSearchFilter.hashCode() : 0);
        result = 31 * result + (userLoginFilter != null ? userLoginFilter.hashCode() : 0);
        result = 31 * result + (userNameAttribute != null ? userNameAttribute.hashCode() : 0);
        result = 31 * result + (displayNameAttribute != null ? displayNameAttribute.hashCode() : 0);
        result = 31 * result + (emailAttribute != null ? emailAttribute.hashCode() : 0);
        result = 31 * result + (certificate != null ? certificate.hashCode() : 0);
        result = 31 * result + (startTLS ? 1 : 0);
        result = 31 * result + (searchTimeout != null ? searchTimeout.hashCode() : 0);
        return result;
    }
}
