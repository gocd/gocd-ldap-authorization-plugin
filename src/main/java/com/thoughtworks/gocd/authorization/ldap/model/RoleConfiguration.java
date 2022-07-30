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

package com.thoughtworks.gocd.authorization.ldap.model;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.thoughtworks.gocd.authorization.ldap.annotation.MetadataHelper;
import com.thoughtworks.gocd.authorization.ldap.annotation.ProfileField;
import com.thoughtworks.gocd.authorization.ldap.utils.Util;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Map;

public class RoleConfiguration {
    public static final String GROUP_MEMBERSHIP_FILTER = "GroupMembershipFilter";
    public static final String USER_GROUP_MEMBERSHIP_ATTRIBUTE = "UserGroupMembershipAttribute";
    public static final String GROUP_IDENTIFIERS = "GroupIdentifiers";
    public static final String GROUP_SEARCH_BASES = "GroupSearchBases";

    @Expose
    @SerializedName(USER_GROUP_MEMBERSHIP_ATTRIBUTE)
    @ProfileField(key = USER_GROUP_MEMBERSHIP_ATTRIBUTE, required = false, secure = false)
    private String userGroupMembershipAttribute;

    @Expose
    @SerializedName(GROUP_IDENTIFIERS)
    @ProfileField(key = GROUP_IDENTIFIERS, required = false, secure = false)
    private String groupIdentifiers;

    @Expose
    @SerializedName(GROUP_SEARCH_BASES)
    @ProfileField(key = GROUP_SEARCH_BASES, required = false, secure = false)
    private String groupSearchBases;

    @Expose
    @SerializedName(GROUP_MEMBERSHIP_FILTER)
    @ProfileField(key = GROUP_MEMBERSHIP_FILTER, required = false, secure = false)
    private String groupMembershipFilter;

    public String getUserGroupMembershipAttribute() {
        return userGroupMembershipAttribute;
    }

    public String getGroupMembershipFilter() {
        return Util.encloseParentheses(groupMembershipFilter);
    }

    public List<String> getGroupIdentifiers() {
        return Util.splitIntoLinesAndTrimSpaces(groupIdentifiers);
    }

    public boolean hasGroupMembershipAttributes() {
        return StringUtils.isNoneBlank(getUserGroupMembershipAttribute()) && !getGroupIdentifiers().isEmpty();
    }

    public List<String> getGroupSearchBases() {
        return Util.splitIntoLinesAndTrimSpaces(groupSearchBases);
    }

    public boolean hasGroupMembershipFilter() {
        return StringUtils.isNoneBlank(getGroupMembershipFilter());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RoleConfiguration that = (RoleConfiguration) o;

        if (userGroupMembershipAttribute != null ? !userGroupMembershipAttribute.equals(that.userGroupMembershipAttribute) : that.userGroupMembershipAttribute != null)
            return false;
        if (groupIdentifiers != null ? !groupIdentifiers.equals(that.groupIdentifiers) : that.groupIdentifiers != null)
            return false;
        if (groupMembershipFilter != null ? !groupMembershipFilter.equals(that.groupMembershipFilter) : that.groupMembershipFilter != null)
            return false;
        return groupSearchBases != null ? groupSearchBases.equals(that.groupSearchBases) : that.groupSearchBases == null;
    }

    @Override
    public int hashCode() {
        int result = userGroupMembershipAttribute != null ? userGroupMembershipAttribute.hashCode() : 0;
        result = 31 * result + (groupIdentifiers != null ? groupIdentifiers.hashCode() : 0);
        result = 31 * result + (groupMembershipFilter != null ? groupMembershipFilter.hashCode() : 0);
        result = 31 * result + (groupSearchBases != null ? groupSearchBases.hashCode() : 0);
        return result;
    }

    public static ValidationResult validate(Map<String, String> properties) {
        return MetadataHelper.validate(RoleConfiguration.class, properties);
    }
}
