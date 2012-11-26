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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import static org.fest.assertions.Assertions.assertThat;

public abstract class LocalSslContextFactoryTest {

  protected LocalSslContextFactory sslContextFactory;
  protected Certificate trustedCertificateOfCA;

  @BeforeClass
  public void setupClass() {
    Security.addProvider(new BouncyCastleProvider());
    trustedCertificateOfCA = getCertificate("serverCA.bks", "serverCA");
  }

  @BeforeMethod
  public void setUp() throws Exception {
    InputStream certAsStream = getClass().getClassLoader().getResourceAsStream("serverCA.bks");
    sslContextFactory = new LocalSslContextFactory(certAsStream, "BKS", null);
  }

  protected abstract LocalSslContext createSslContext();

  protected abstract Class<? extends X509TrustManager> getTrustManagerType();

  @Test
  public void testSslContextUsesTLSv1() {
    LocalSslContext sslContext = createSslContext();
    assertThat(sslContext.getProtocol()).isEqualTo("TLSv1");
  }

  @Test
  public void testCreatesSslContextWithUniqueTrustManager() {
    LocalSslContext sslContext = createSslContext();

    assertThat(sslContext.getTrustManagers()).hasSize(1);
    TrustManager uniqueTrustManager = sslContext.getTrustManagers().get(0);
    assertThat(uniqueTrustManager).isInstanceOf(getTrustManagerType());
  }

  @Test
  public void testCreatesSslContextWithTrustManagerUsingServerCACertificate() {
    LocalSslContext sslContext = createSslContext();
    X509TrustManager x509TrustManager = (X509TrustManager) sslContext.getTrustManagers().get(0);
    assertThat(x509TrustManager.getAcceptedIssuers()).contains(trustedCertificateOfCA);
  }

  private Certificate getCertificate(String resourceName, String certificateAlias) {
    InputStream certAsStream = getClass().getClassLoader().getResourceAsStream(resourceName);
    try {
      KeyStore localTrustStore = KeyStore.getInstance("BKS");
      localTrustStore.load(certAsStream, null);
      return localTrustStore.getCertificate(certificateAlias);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
