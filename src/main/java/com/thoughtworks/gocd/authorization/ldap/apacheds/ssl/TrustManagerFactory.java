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

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.UUID;

import static com.thoughtworks.gocd.authorization.ldap.LdapPlugin.LOG;
import static java.text.MessageFormat.format;

public class TrustManagerFactory {
    public static final String KEYSTORE_PASSWD = UUID.randomUUID().toString();
    private static final TrustManagerFactory INSTANCE = new TrustManagerFactory();

    private TrustManagerFactory() {
    }

    public X509TrustManager getTrustManager(Certificate certificate) {
        return trustManager(certificate);
    }

    private X509TrustManager trustManager(final Certificate certificate) {
        try {
            KeyStore keyStore = null;
            if (certificate != null) {
                keyStore = createInMemoryKeyStore(certificate);
            } else {
                LOG.debug("Server certificate not configured. Falling back to default truststore.");
            }

            javax.net.ssl.TrustManagerFactory trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

            for (int i = 0; i < trustManagers.length; i++) {
                if (trustManagers[i] instanceof X509TrustManager) {
                    X509TrustManager trustManager = (X509TrustManager) trustManagers[i];
                    LOG.debug(format("Found X509TrustManager {0}.", trustManager));
                    return trustManager;
                }
            }

            throw new RuntimeException("Failed to find X509 trustmanager from keystore.");
        } catch (Exception e) {
            LOG.error("Failed to initialize the keystore and X509 trustmanager.", e);
            throw new RuntimeException(e);
        }
    }

    public static TrustManagerFactory getInstance() {
        return INSTANCE;
    }

    private KeyStore createInMemoryKeyStore(Certificate certificate) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            LOG.debug(format("Loading in memory keystore using password {0}.", KEYSTORE_PASSWD));
            keyStore.load(null, KEYSTORE_PASSWD.toCharArray());

            addCertificate(certificate, keyStore);

            return keyStore;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException("Failed to create in memory keystore", e);
        }
    }

    private void addCertificate(Certificate certificate, KeyStore keyStore) throws NoSuchAlgorithmException, KeyStoreException {
        if (certificate == null) {
            LOG.debug("Cannot add null certificate to keystore.");
            return;
        }

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        LOG.debug("Adding certificate to keystore.");
        keyStore.setCertificateEntry("cert", certificate);
        keyStore.setKeyEntry("private", keyPair.getPrivate(), KEYSTORE_PASSWD.toCharArray(), new Certificate[]{certificate});
        LOG.debug("Certificate successfully added to keystore.");
    }
}
