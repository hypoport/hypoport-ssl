/**
 *  Copyright 2012 HYPOPORT AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.hypoport.ssl;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.net.ssl.X509TrustManager;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static java.security.cert.CertificateFactory.getInstance;
import static org.fest.assertions.Assertions.assertThat;

@Test
public abstract class LocalTrustManagerTest {

  protected X509TrustManager x509TrustManager;
  protected X509Certificate certificateOfIssuingCA;

  @BeforeMethod
  public void setUp() throws Exception {
    certificateOfIssuingCA = getX509Certificate("serverCA.pem");

    KeyStore keyStore = loadEmptyKeyStore();
    keyStore.setCertificateEntry("CA-Cert", certificateOfIssuingCA);
    x509TrustManager = createTrustManager(keyStore);
  }

  protected abstract X509TrustManager createTrustManager(KeyStore keyStore);

  @Test
  public void testAcceptedIssuersContainExpectedCertificateAuthority() {
    X509Certificate[] acceptedIssuers = x509TrustManager.getAcceptedIssuers();
    List<X509Certificate> acceptedIssuersAsList = Arrays.asList(acceptedIssuers);
    assertThat(acceptedIssuersAsList).contains(certificateOfIssuingCA);
  }

  @Test
  public void testTrustsServerCertificateIssuedByKnownCA() throws Exception {
    X509Certificate certificateOfServer = getX509Certificate("serverCert.pem");
    x509TrustManager.checkServerTrusted(new X509Certificate[] {certificateOfServer}, "RSA");
  }

  private X509Certificate getX509Certificate(String resourceName) throws Exception {
    InputStream certAsStream = getClass().getClassLoader().getResourceAsStream(resourceName);
    BufferedInputStream bis = new BufferedInputStream(certAsStream);
    X509Certificate certificate = (X509Certificate) getInstance("X.509").generateCertificate(bis);
    bis.close();
    return certificate;
  }

  private KeyStore loadEmptyKeyStore() throws Exception {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    return keyStore;
  }
}
