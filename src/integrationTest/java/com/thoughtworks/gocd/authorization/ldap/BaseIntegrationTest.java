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

import com.google.gson.Gson;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.util.Network;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.ApacheDSTestExtension;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static javax.naming.ldap.Control.CRITICAL;

@ExtendWith(ApacheDSTestExtension.class)
public abstract class BaseIntegrationTest extends AbstractLdapTestUnit {
    public static final String SERVER_HOSTNAME = "localhost";
    public static final String SERVER_ISSUER_DN = "system";

    public static final String APACHE_DS_KEYSTORE_PASSWORD = "secret";
    public static final String APACHE_DS_KEYSTORE_CERT_ALIAS = "apacheDsKey";

    private String serverCertificatePem = null;

    @BeforeEach
    public void changeTestServerCertificate() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509Certificate certificate = generateLoopbackCertificate(
                new X500Principal("CN=" + BaseIntegrationTest.SERVER_HOSTNAME + ",OU=directory,O=apache,C=US"),
                new X500Principal("CN=" + BaseIntegrationTest.SERVER_ISSUER_DN + ",OU=directory,O=apache,C=US"),
                keyPair);
        reloadWithCertificate(certificate, keyPair);

        serverCertificatePem = toPem(certificate);
    }

    protected LdapConfiguration ldapConfiguration(String[] searchBases) {
        return ldapConfigurationWithValidCert("ldap", searchBases);
    }

    protected LdapConfiguration ldapConfigurationWithValidCert(String urlScheme, String[] searchBases) {
        return ldapConfiguration(urlScheme, searchBases, serverCertificatePem);
    }

    private String toPem(Certificate certificate) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(certificate);
        }
        return sw.toString();
    }

    protected LdapConfiguration ldapConfigurationWithInvalidCert(String[] searchBases) {
        return ldapConfiguration("ldaps", searchBases, INVALID_CERT);
    }

    private LdapConfiguration ldapConfiguration(String urlScheme, String[] searchBases, String cert) {
        int port = urlScheme.equalsIgnoreCase("ldaps") ? ldapServer.getPortSSL() : ldapServer.getPort();

        final Map<String, String> configuration = new HashMap<>();
        configuration.put("Url", String.format("%s://%s:%s", urlScheme, SERVER_HOSTNAME, port));
        configuration.put("SearchBases", StringUtils.join(searchBases, "\n"));
        configuration.put("ManagerDN", "uid=admin,ou=" + SERVER_ISSUER_DN);
        configuration.put("Password", APACHE_DS_KEYSTORE_PASSWORD);
        configuration.put("UserLoginFilter", "(uid={0})");
        configuration.put("UserSearchFilter", "(cn={0})");
        configuration.put("UserNameAttribute", "uid");
        configuration.put("DisplayNameAttribute", "displayName");
        configuration.put("Certificate", cert);

        return LdapConfiguration.fromJSON(new Gson().toJson(configuration));
    }

    private void reloadWithCertificate(Certificate certificate, KeyPair keyPair) throws Exception {
        String keyStoreFile = classLdapServer.getKeystoreFile();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] keyStorePassword = BaseIntegrationTest.APACHE_DS_KEYSTORE_PASSWORD.toCharArray();

        try (InputStream ignore = new FileInputStream(keyStoreFile)) {
            keyStore.load((InputStream)null, keyStorePassword);
        }

        keyStore.setKeyEntry(APACHE_DS_KEYSTORE_CERT_ALIAS, keyPair.getPrivate(), keyStorePassword, new Certificate[]{certificate});

        try (FileOutputStream out = new FileOutputStream(keyStoreFile)) {
            keyStore.store(out, keyStorePassword);
        }
        classLdapServer.reloadSslContext();
    }

    /**
     * Adapter from ApacheDS since the generated cert does not include the SAN for loopback, so doesn't work properly
     * @see org.apache.directory.server.core.security.CertificateUtil#generateX509Certificate(X500Principal, X500Principal, KeyPair, long, String, boolean)
     */
    private X509Certificate generateLoopbackCertificate(X500Principal subjectDn, X500Principal issuerDn, KeyPair keyPair) throws CertificateException {
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        try {
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA").build(keyPair.getPrivate());
            GeneralName[] sanLocalHost = new GeneralName[]{
                    new GeneralName(GeneralName.dNSName, Network.LOOPBACK_HOSTNAME),
            };
            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuerDn,
                    serialNumber,
                    Date.from(Instant.now()),
                    Date.from(Instant.now().plus(Duration.ofDays(365))),
                    subjectDn,
                    keyPair.getPublic())
                    .addExtension(Extension.basicConstraints, CRITICAL, new BasicConstraints(true))
                    .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sanLocalHost));

            return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(signer));
        } catch (OperatorCreationException | CertIOException e) {
            throw new CertificateException("BouncyCastle failed to generate the X509 certificate.", e);
        }
    }

    private static final String INVALID_CERT = """
            -----BEGIN CERTIFICATE-----
            MIICwTCCAamgAwIBAgIECuCFsDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQLEwZz
            eXN0ZW0wHhcNMTcwODI2MDU1ODQwWhcNMTkwODI2MDU1ODQwWjARMQ8wDQYDVQQL
            EwZzeXN0ZW0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCHfHQfswt9
            oEkrjpkMPVFbTnqPkB4TSSwmK5/hzSxEiitc+HqMJyPqmdgqzcvnPnOqE4McUiA8
            UX2VKB9cjOk4hfo+qJYqvXzkCRhnz2tbJJZEt2eXBiMDpOlHF1Amcsy0W+R6Ac+h
            IfRq1h7JaVxfnmVjAuXh4JygKIZiUjjCWb5bX9BnMD5xVLlqTkXhuFgXW3ZRKU8T
            QFWbRtFSKEKWkgh7A01jN3Jxn2CRMJBa9HCnECcfdGym7Qly/BtdmjYwqtnCweJ4
            yG0CRshzZ6CMmDHst+VE25e0Ju1zHU/bIUjY+pos80rK+ox1toy9Fdc9PMLMw4Ph
            GSnoWJhIKYj3AgMBAAGjITAfMB0GA1UdDgQWBBTijSEodc+jwyCvY4a0bQO+K0nl
            IDANBgkqhkiG9w0BAQsFAAOCAQEAGZGrEMQYwrf8M7is5BngFNBXnuGWcp+RcBW/
            VUVS0GEfrA4fLEf+VJd2+TxOgQHlGe0duJEyVRnpvYoNjFbmKWc5EGoIHYkTNdbh
            m9zi8KReL17ktPsTnFcPw2a4rTbIjg2SEgo8wTaEtMT/P2ZSxGMr+1WFtjDEFN4c
            yif96h8DOvo4JuP6E2V2pPic6Jb/aWGfpVEfRd513ymn3JuGReHCCaCs2hZzeONy
            3Bhlnubk3tmoSf0Cj45LtKhc3RMHPMvDayc5BO5CZTWlLrK12rDmPYKffy7lLjO5
            mPhe6p/SOAanBhL/+WwsYjPG8R/A0iQE1tUTsOy+Xo/xEyPpgw==
            -----END CERTIFICATE-----
            """;
}
