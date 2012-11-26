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

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm;
import static org.hypoport.ssl.X509TrustManagerFinder.findX509TrustManager;

class LocalAndDefaultTrustManager implements X509TrustManager {

  private X509TrustManager defaultTrustManager;
  private X509TrustManager localTrustManager;

  private X509Certificate[] acceptedIssuers;

  public LocalAndDefaultTrustManager(KeyStore localTrustStore) {
    List<X509Certificate> allIssuers = new ArrayList<X509Certificate>();

    localTrustManager = initLocalTrustManager(localTrustStore);
    allIssuers.addAll(asList(localTrustManager.getAcceptedIssuers()));

    defaultTrustManager = initDefaultTrustManager();
    allIssuers.addAll(asList(defaultTrustManager.getAcceptedIssuers()));

    acceptedIssuers = allIssuers.toArray(new X509Certificate[allIssuers.size()]);
  }

  private X509TrustManager initLocalTrustManager(KeyStore localTrustStore) {
    return new LocalOnlyTrustManager(localTrustStore);
  }

  private X509TrustManager initDefaultTrustManager() {
    try {
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(getDefaultAlgorithm());
      tmf.init((KeyStore) null);
      return findX509TrustManager(tmf);
    }
    catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    try {
      checkClientTrustedWithLocalTrustManager(chain, authType);
    }
    catch (CertificateException ce) {
      checkClientTrustedWithDefaultTrustManager(chain, authType);
    }
  }

  private void checkClientTrustedWithLocalTrustManager(X509Certificate[] chain, String authType) throws CertificateException {
    localTrustManager.checkClientTrusted(chain, authType);
  }

  private void checkClientTrustedWithDefaultTrustManager(X509Certificate[] chain, String authType) throws CertificateException {
    defaultTrustManager.checkClientTrusted(chain, authType);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    try {
      checkServerTrustedWithLocalTrustManager(chain, authType);
    }
    catch (CertificateException ce) {
      checkServerTrustedWithDefaultTrustManager(chain, authType);
    }
  }

  private void checkServerTrustedWithLocalTrustManager(X509Certificate[] chain, String authType) throws CertificateException {
    localTrustManager.checkServerTrusted(chain, authType);
  }

  private void checkServerTrustedWithDefaultTrustManager(X509Certificate[] chain, String authType) throws CertificateException {
    defaultTrustManager.checkServerTrusted(chain, authType);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return acceptedIssuers;
  }
}
