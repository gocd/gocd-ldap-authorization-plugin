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

package com.thoughtworks.gocd.authorization.ldap.apacheds.ssl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SystemStubsExtension.class)
public class TrustManagerFactoryTest {

    @SystemStub
    public SystemProperties systemProperties;

    @Test
    public void shouldGetTrustManagerWithCustomCertificate() throws Exception {
        final TrustManagerFactory instance = TrustManagerFactory.getInstance();
        final X509Certificate certificate = loadCertificate();

        final X509TrustManager trustManager = instance.getTrustManager(certificate);

        final List<X509Certificate> acceptedIssuers = Arrays.asList(trustManager.getAcceptedIssuers());

        assertThat(acceptedIssuers).contains(certificate);
    }

    @Test
    public void shouldGetTrustManagerWithDefaultTrustStoreInAbsenceOfCertificate() throws Exception {
        systemProperties.set("javax.net.ssl.trustStore", TrustManagerFactory.class.getResource("/test-truststore").getFile());
        final TrustManagerFactory instance = TrustManagerFactory.getInstance();

        final X509TrustManager trustManager = instance.getTrustManager(null);

        final List<X509Certificate> acceptedIssuers = Arrays.asList(trustManager.getAcceptedIssuers());

        assertThat(acceptedIssuers).contains(loadCertificate());
    }

    private X509Certificate loadCertificate() throws CertificateException {
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(TrustManagerFactory.class.getResourceAsStream("/example-cert.pem"));
    }
}
