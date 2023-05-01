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

package com.thoughtworks.gocd.authorization.ldap.validators;

import com.thoughtworks.gocd.authorization.ldap.LdapConfigurationMother;
import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationError;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;
import org.junit.jupiter.api.Test;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateValidatorTest {

    private final String EXPIRED_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIBnTCCAQagAwIBAgIIZ4GQMRkdfkYwDQYJKoZIhvcNAQEFBQAwETEPMA0GA1UECxMGc3lzdGVt\n" +
            "MB4XDTE3MDgyOTA5MzkxMFoXDTE3MDgzMDA5MzkxMFowETEPMA0GA1UECxMGc3lzdGVtMIGfMA0G\n" +
            "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQCt9ocr5IinlQuYLsQvjGG1Uc0avTrmJflaucDFigYKmBru\n" +
            "x5WYRIteaGHwdnFua0zM1X69Zbdo9zIA5GAh/6nMxY0m2DBVzxYFnYHpeW2YRKqx+W+vIcxHWMIM\n" +
            "CJ7E/FQo4LjVTLHYyYewg417LHBT+fBnboghojylT5JiZZ4JrQIDAQABMA0GCSqGSIb3DQEBBQUA\n" +
            "A4GBAEgX8+fG4wiGZ0aLRBvgY/rGcUjaVbqS/f88SaHOrXl/PcghG6sUXcszVcVOFFNKDTSvTiTf\n" +
            "rozRC1QG/Gh6J5oXD3mZES7Z8AGKuWf9HYGKbBmBmFsHjBJVjN0z3xceHfrB2Xq0knjk2Ud16syy\n" +
            "vAJAehC2qMaw2tKYN8f1frqd-----END CERTIFICATE-----";
    private final ZonedDateTime EXPIRY_DATE = ZonedDateTime.of(2017, 8, 30, 9, 39, 0, 0, ZoneId.of("UTC"));

    private final String VALID_CERT_TEXT = "-----BEGIN CERTIFICATE-----\n" +
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

    @Test
    public void shouldValidateValidCertificate() throws Exception {
        final LdapConfiguration configuration = new LdapConfigurationMother.Builder()
                .withURL("ldap://localhost:389")
                .withCertificate(VALID_CERT_TEXT)
                .build();

        final ValidationResult result = new CertificateValidator().validate(configuration);

        assertFalse(result.hasErrors());
    }

    @Test
    public void shouldReturnErrorIfCertificateTextIsInvalid() throws Exception {
        final LdapConfiguration configuration = new LdapConfigurationMother.Builder()
                .withURL("ldap://localhost:389")
                .withCertificate("random-text")
                .build();

        final ValidationResult result = new CertificateValidator().validate(configuration);

        assertTrue(result.hasErrors());
        assertThat(result.allErrors()).hasSize(1);

        final ValidationError validationError = result.allErrors().get(0);
        assertThat(validationError.key()).isEqualTo("Certificate");
        assertThat(validationError.message()).isEqualTo("Error parsing certificate - `Could not parse certificate: java.io.IOException: Empty input`");
    }

    @Test
    public void shouldReturnErrorIfCertificateIsExpired() throws Exception {
        final LdapConfiguration configuration = new LdapConfigurationMother.Builder()
                .withURL("ldap://localhost:389")
                .withCertificate(EXPIRED_CERT)
                .build();

        final ValidationResult result = new CertificateValidator().validate(configuration);

        assertTrue(result.hasErrors());
        assertThat(result.allErrors()).hasSize(1);

        final ValidationError validationError = result.allErrors().get(0);
        assertThat(validationError.key()).isEqualTo("Certificate");
        assertThat(validationError.message()).startsWith("Invalid Certificate, expired on `" + EXPIRY_DATE.format(DateTimeFormatter.ofLocalizedDate(FormatStyle.SHORT)));
    }
}
