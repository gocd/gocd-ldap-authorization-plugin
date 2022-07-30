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

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.text.MessageFormat.format;

public class LdapSearchFilterBuilder {
    private final static Pattern PATTERN = Pattern.compile("\\{(.*?)\\}");

    public String build(String filterExpression, Entry entry) {
        final Set<Match> matches = getExpressions(filterExpression);

        for (Match match : matches) {
            filterExpression = filterExpression.replace(match.expression, getAttributeValue(filterExpression, entry, match));
        }
        return filterExpression;
    }

    private String getAttributeValue(String filterExpression, Entry entry, Match match) {
        if (match.content.equalsIgnoreCase("dn")) {
            return entry.getDn().toString();
        }

        final Attribute attribute = entry.get(match.content);
        if (attribute == null) {
            throw new RuntimeException(format("Failed to build search filter `{0}`. Missing attribute for the expression `{1}`", filterExpression, match.content));
        }
        return attribute.get().getString();
    }

    private Set<Match> getExpressions(String filterExpression) {
        Set<Match> matches = new HashSet<>();
        Matcher matcher = PATTERN.matcher(filterExpression);
        while (matcher.find()) {
            matches.add(new Match(matcher.group(), matcher.group(1)));
        }
        return matches;
    }

    private class Match {
        private final String expression;
        private final String content;

        Match(String expression, String content) {
            this.expression = expression;
            this.content = content;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Match match = (Match) o;

            if (expression != null ? !expression.equals(match.expression) : match.expression != null) return false;
            return content != null ? content.equals(match.content) : match.content == null;
        }

        @Override
        public int hashCode() {
            int result = expression != null ? expression.hashCode() : 0;
            result = 31 * result + (content != null ? content.hashCode() : 0);
            return result;
        }
    }
}
