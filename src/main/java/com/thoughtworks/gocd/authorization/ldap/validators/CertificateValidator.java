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

package com.thoughtworks.gocd.authorization.ldap.validators;

import com.thoughtworks.gocd.authorization.ldap.model.LdapConfiguration;
import com.thoughtworks.gocd.authorization.ldap.model.ValidationResult;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import static java.text.MessageFormat.format;
import static org.apache.commons.lang3.StringUtils.isBlank;

public class CertificateValidator implements Validatable {

    @Override
    public ValidationResult validate(LdapConfiguration ldapConfiguration) {
        final ValidationResult validationResult = new ValidationResult();

        X509Certificate certificate = null;
        try {
            final String certificateText = ldapConfiguration.getCertificate();
            if (isBlank(certificateText)) {
                return validationResult;
            }
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateText.getBytes()));

            certificate.checkValidity();
        } catch (CertificateExpiredException e) {
            validationResult.addError("Certificate", format("Invalid Certificate, expired on `{0}`", certificate.getNotAfter()));
        } catch (CertificateNotYetValidException e) {
            validationResult.addError("Certificate", format("Invalid Certificate, valid from `{0}`", certificate.getNotBefore()));
        } catch (Exception e) {
            validationResult.addError("Certificate", format("Error parsing certificate - `{0}`", e.getMessage()));
        }

        return validationResult;
    }
}
