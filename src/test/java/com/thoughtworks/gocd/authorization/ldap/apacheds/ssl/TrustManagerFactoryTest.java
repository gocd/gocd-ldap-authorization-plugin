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

package com.thoughtworks.gocd.authorization.ldap.apacheds.ssl;

import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.RestoreSystemProperties;

import javax.net.ssl.X509TrustManager;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertThat;

public class TrustManagerFactoryTest {

    @Rule
    public final RestoreSystemProperties restoreSystemProperties = new RestoreSystemProperties();

    @Test
    public void shouldGetTrustManagerWithCustomCertificate() throws Exception {
        final TrustManagerFactory instance = TrustManagerFactory.getInstance();
        final Certificate certificate = loadCertificate();

        final X509TrustManager trustManager = instance.getTrustManager(certificate);

        final List<X509Certificate> acceptedIssuers = Arrays.asList(trustManager.getAcceptedIssuers());

        assertThat(acceptedIssuers, contains(certificate));
    }

    @Test
    public void shouldGetTrustManagerWithDefaultTrustStoreInAbsenceOfCertificate() throws Exception {
        System.setProperty("javax.net.ssl.trustStore", TrustManagerFactory.class.getResource("/test-truststore").getFile());
        final TrustManagerFactory instance = TrustManagerFactory.getInstance();

        final X509TrustManager trustManager = instance.getTrustManager(null);

        final List<X509Certificate> acceptedIssuers = Arrays.asList(trustManager.getAcceptedIssuers());

        assertThat(acceptedIssuers, contains(loadCertificate()));
    }

    private Certificate loadCertificate() throws CertificateException {
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificate(TrustManagerFactory.class.getResourceAsStream("/example-cert.pem"));
    }
}
