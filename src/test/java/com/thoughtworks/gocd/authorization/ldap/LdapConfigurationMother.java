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

package com.thoughtworks.gocd.authorization.ldap;

import com.google.gson.Gson;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class LdapConfigurationMother {

    public static class Builder {
        final Map<String, Object> configuration = new HashMap<>();

        public Builder() {
            configuration.put("Url", "ldap://localhost:389");
            configuration.put("SearchBases", "ou=system");
            configuration.put("ManagerDN", "uid=admin,ou=system");
            configuration.put("Password", "secret");
            configuration.put("UserLoginFilter", "(uid={0})");
            configuration.put("UserNameAttribute", "uid");
            configuration.put("Certificate", DUMMY_CERT);
        }

        public Builder withURL(String url) {
            this.configuration.put("Url", url);
            return this;
        }

        public Builder withSearchBases(String... searchBases) {
            this.configuration.put("SearchBases", StringUtils.join(searchBases, "\n"));
            return this;
        }

        public Builder withManagerDN(String managerDN) {
            this.configuration.put("ManagerDN", managerDN);
            return this;
        }

        public Builder withUserLoginFilter(String userLoginFilter) {
            this.configuration.put("UserLoginFilter", userLoginFilter);
            return this;
        }

        public Builder withPassword(String password) {
            this.configuration.put("Password", password);
            return this;
        }

        public Builder withUserNameAttribute(String userNameAttribute) {
            this.configuration.put("UserNameAttribute", userNameAttribute);
            return this;
        }

        public Builder withCertificate(String certificate) {
            this.configuration.put("Certificate", certificate);
            return this;
        }

        public Builder withStartTLS(boolean startTLS) {
            this.configuration.put("StartTLS", startTLS);
            return this;
        }

        public Builder withSearchTimeout(int searchTimeout) {
            this.configuration.put("SearchTimeout", searchTimeout);
            return this;
        }

        public final LdapConfiguration build() {
            return LdapConfiguration.fromJSON(new Gson().toJson(configuration));
        }

        private String DUMMY_CERT = "-----BEGIN CERTIFICATE-----\n" +
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
}
