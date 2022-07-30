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
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.junit.runner.RunWith;

import java.util.HashMap;
import java.util.Map;

@RunWith(FrameworkRunner.class)
@ApplyLdifFiles(value = "users.ldif", clazz = BaseIntegrationTest.class)
@CreateLdapServer(
        transports =
                {
                        @CreateTransport(protocol = "LDAP", address = "localhost"),
                        @CreateTransport(protocol = "LDAPS", address = "localhost")
                },
        keyStore = "./src/testdata/ldap.jks",
        certificatePassword = "secret",
        saslHost = "localhost"
)
public abstract class BaseIntegrationTest extends AbstractLdapTestUnit {

    protected LdapConfiguration ldapConfiguration(String[] searchBases) {
        return ldapConfigurationWithValidCert("ldap", searchBases);
    }

    protected LdapConfiguration ldapConfigurationWithValidCert(String urlScheme, String[] searchBases) {
        return ldapConfiguration(urlScheme, searchBases, VALID_CERT);
    }

    protected LdapConfiguration ldapConfigurationWithInvalidCert(String urlScheme, String[] searchBases) {
        return ldapConfiguration(urlScheme, searchBases, INVALID_CERT);
    }

    private LdapConfiguration ldapConfiguration(String urlScheme, String[] searchBases, String cert) {
        int port = urlScheme.equalsIgnoreCase("ldaps") ? ldapServer.getPortSSL() : ldapServer.getPort();

        final Map<String, String> configuration = new HashMap<>();
        configuration.put("Url", String.format("%s://localhost:%s", urlScheme, port));
        configuration.put("SearchBases", StringUtils.join(searchBases, "\n"));
        configuration.put("ManagerDN", "uid=admin,ou=system");
        configuration.put("Password", "secret");
        configuration.put("UserLoginFilter", "(uid={0})");
        configuration.put("UserSearchFilter", "(cn={0})");
        configuration.put("UserNameAttribute", "uid");
        configuration.put("DisplayNameAttribute", "displayName");
        configuration.put("Certificate", cert);

        return LdapConfiguration.fromJSON(new Gson().toJson(configuration));
    }

    private static String VALID_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIICwTCCAamgAwIBAgIEf41zDzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQLEwZzeXN0ZW0wHhcN\n" +
            "MTcwODI3MDgzOTQ1WhcNMzcwODIyMDgzOTQ1WjARMQ8wDQYDVQQLEwZzeXN0ZW0wggEiMA0GCSqG\n" +
            "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCA8CFA15j9HE6NXk76041oQovq09JpV+a7ISMr6DTaC9/W\n" +
            "87Snk8bJptj+gO9HTMBOEzXbgc09ZkEa9binjbY1hpKJf7VAnX42cddfKEbPHG28dDtDzX7jfiNe\n" +
            "qGGTQOa46Ipowz7ZjvMaKp44aDvet4vxVpjp176eXnpxgBmki5d6AKX2dnqJKNY7pwpXuROJw8D6\n" +
            "wrjSuf/VoyqnCttFKWb0FXAxkQlay6h8kHgTLxYFHGmcJLTktFa2CQQU4eZJOV4JPXNMhQJPWUBs\n" +
            "sTcMKJIk3pjK6ekQfc20GxgckfRDRUCjk8AQ6flsSVU8uz4iVjNq/ap+ymChLXgdm5JLAgMBAAGj\n" +
            "ITAfMB0GA1UdDgQWBBR9wSOVHa3+ta0IBJMq24kSHSsuETANBgkqhkiG9w0BAQsFAAOCAQEASplY\n" +
            "QlSxKJWYK2pzfZQ7I87qDpZstm2cw5wIfCA9NLUZruODExexUfEXpUersG9IECxvhHrTI4JSN+Nk\n" +
            "g8l25CZHuonO3Wkv9cEITBwdLeAjHGoPfXpkFbMZKeJC6erqwpsTlZbmoUFRE+F/b2+jN5AkJhKM\n" +
            "MskcUxuDk2bJ9OIwJMkU7/8QoZMm5ecgQVPdVPe3DHetPD36db5o3j5uOcFDH/YghssR4J+qNMI3\n" +
            "DHcOCshgBqGaaHLlBvzvBsNZAzWYWJ+3ydh5cJAyWwXnRp6xSaIpHesuABi2ipv0HN90SQQP0dAe\n" +
            "bRgEaG0k5Hahzbtte3nXwdcJQmwD0vusbQ==\n" +
            "-----END CERTIFICATE-----\n";

    private static String INVALID_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIICwTCCAamgAwIBAgIECuCFsDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQLEwZz\n" +
            "eXN0ZW0wHhcNMTcwODI2MDU1ODQwWhcNMTkwODI2MDU1ODQwWjARMQ8wDQYDVQQL\n" +
            "EwZzeXN0ZW0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCHfHQfswt9\n" +
            "oEkrjpkMPVFbTnqPkB4TSSwmK5/hzSxEiitc+HqMJyPqmdgqzcvnPnOqE4McUiA8\n" +
            "UX2VKB9cjOk4hfo+qJYqvXzkCRhnz2tbJJZEt2eXBiMDpOlHF1Amcsy0W+R6Ac+h\n" +
            "IfRq1h7JaVxfnmVjAuXh4JygKIZiUjjCWb5bX9BnMD5xVLlqTkXhuFgXW3ZRKU8T\n" +
            "QFWbRtFSKEKWkgh7A01jN3Jxn2CRMJBa9HCnECcfdGym7Qly/BtdmjYwqtnCweJ4\n" +
            "yG0CRshzZ6CMmDHst+VE25e0Ju1zHU/bIUjY+pos80rK+ox1toy9Fdc9PMLMw4Ph\n" +
            "GSnoWJhIKYj3AgMBAAGjITAfMB0GA1UdDgQWBBTijSEodc+jwyCvY4a0bQO+K0nl\n" +
            "IDANBgkqhkiG9w0BAQsFAAOCAQEAGZGrEMQYwrf8M7is5BngFNBXnuGWcp+RcBW/\n" +
            "VUVS0GEfrA4fLEf+VJd2+TxOgQHlGe0duJEyVRnpvYoNjFbmKWc5EGoIHYkTNdbh\n" +
            "m9zi8KReL17ktPsTnFcPw2a4rTbIjg2SEgo8wTaEtMT/P2ZSxGMr+1WFtjDEFN4c\n" +
            "yif96h8DOvo4JuP6E2V2pPic6Jb/aWGfpVEfRd513ymn3JuGReHCCaCs2hZzeONy\n" +
            "3Bhlnubk3tmoSf0Cj45LtKhc3RMHPMvDayc5BO5CZTWlLrK12rDmPYKffy7lLjO5\n" +
            "mPhe6p/SOAanBhL/+WwsYjPG8R/A0iQE1tUTsOy+Xo/xEyPpgw==\n" +
            "-----END CERTIFICATE-----\n";
}
