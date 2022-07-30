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

package com.thoughtworks.gocd.authorization.ldap.apacheds;

import com.thoughtworks.gocd.authorization.ldap.apacheds.ssl.TrustManagerFactory;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.MessageFormat;

import static org.apache.commons.lang3.StringUtils.isBlank;

public class ConnectionConfiguration {
    private boolean useSsl = false;
    private int ldapPort;
    private String ldapHost;
    private String managerDn;
    private String password;
    private String certString;
    private boolean startTLS;


    public ConnectionConfiguration(LdapConfiguration ldapConfiguration) {
        this.ldapHost = ldapConfiguration.getLdapUrl().getHost();
        this.ldapPort = getPort(ldapConfiguration);
        this.useSsl = ldapConfiguration.useSSL();
        this.certString = ldapConfiguration.getCertificate();
        this.managerDn = ldapConfiguration.getManagerDn();
        this.password = ldapConfiguration.getPassword();
        this.startTLS = ldapConfiguration.startTLS();
        this.certString = ldapConfiguration.getCertificate();
    }

    private int getPort(LdapConfiguration ldapConfiguration) {
        final int port = ldapConfiguration.getLdapUrl().getPort();

        if (port != -1) {
            return port;
        }

        return ldapConfiguration.useSSL() ? 636 : 389;
    }

    public LdapConnectionConfig toLdapConnectionConfig() {
        return toLdapConnectionConfig(this.managerDn, this.password);
    }

    public LdapConnectionConfig toLdapConnectionConfig(String dn, String password) {
        final LdapConnectionConfig config = new LdapConnectionConfig();
        config.setLdapHost(this.ldapHost);
        config.setLdapPort(this.ldapPort);
        config.setUseSsl(this.useSsl);
        config.setUseTls(this.startTLS);

        if (StringUtils.isNoneBlank(dn, password)) {
            config.setName(dn);
            config.setCredentials(password);
        }

        config.setTrustManagers(TrustManagerFactory.getInstance().getTrustManager(toCertificate(this.certString)));

        return config;
    }

    private Certificate toCertificate(String certString) {
        if (isBlank(certString)) {
            return null;
        }

        try {
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificate(new ByteArrayInputStream(certString.getBytes()));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ConnectionConfiguration that = (ConnectionConfiguration) o;

        if (useSsl != that.useSsl) return false;
        if (ldapPort != that.ldapPort) return false;
        if (startTLS != that.startTLS) return false;
        if (ldapHost != null ? !ldapHost.equals(that.ldapHost) : that.ldapHost != null) return false;
        if (managerDn != null ? !managerDn.equals(that.managerDn) : that.managerDn != null) return false;
        if (password != null ? !password.equals(that.password) : that.password != null) return false;
        return certString != null ? certString.equals(that.certString) : that.certString == null;
    }

    @Override
    public int hashCode() {
        int result = (useSsl ? 1 : 0);
        result = 31 * result + ldapPort;
        result = 31 * result + (ldapHost != null ? ldapHost.hashCode() : 0);
        result = 31 * result + (managerDn != null ? managerDn.hashCode() : 0);
        result = 31 * result + (password != null ? password.hashCode() : 0);
        result = 31 * result + (certString != null ? certString.hashCode() : 0);
        result = 31 * result + (startTLS ? 1 : 0);
        return result;
    }

    @Override
    public String toString() {
        return MessageFormat.format("ConnectionConfiguration'{'useSsl={0}, ldapPort={1}, ldapHost=''{2}'', managerDn=''{3}'', password=''{4}'', certString=''{5}'', startTLS={6}'}'", useSsl, ldapPort, ldapHost, managerDn, password, certString, startTLS);
    }
}
