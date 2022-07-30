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
import com.thoughtworks.gocd.authorization.ldap.exception.InvalidUsernameException;
import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.entry.Entry;

public class User {
    @Expose
    @SerializedName("username")
    private String username;

    @Expose
    @SerializedName("display_name")
    private String displayName;

    @Expose
    @SerializedName("email")
    private String emailId;

    private transient final Entry entry;

    public User(String username, String displayName, String emailId) {
        this(username, displayName, emailId, null);
    }

    public User(String username, String displayName, String emailId, Entry entry) {
        this.username = username;
        this.displayName = displayName;
        this.emailId = emailId == null ? null : emailId.toLowerCase().trim();
        this.entry = entry;

        if (StringUtils.isBlank(this.username)) {
            throw new InvalidUsernameException("Username can not be blank. Please check `SearchFilter` attribute on `<authConfig>` profile.");
        }
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName != null && displayName.length() > 0 ? displayName : username;
    }

    public String getEmailId() {
        return emailId;
    }

    public Entry getEntry() {
        return entry;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        User user = (User) o;

        if (displayName != null ? !displayName.equals(user.displayName) : user.displayName != null) return false;
        if (emailId != null ? !emailId.equals(user.emailId) : user.emailId != null) return false;
        if (username != null ? !username.equals(user.username) : user.username != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (displayName != null ? displayName.hashCode() : 0);
        result = 31 * result + (emailId != null ? emailId.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return new StringBuilder("User@{username=").append(username)
                .append(", displayName=").append(displayName)
                .append(", emailId=").append(emailId)
                .append("}").toString();
    }
}
