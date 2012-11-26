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

import static javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm;
import static org.hypoport.ssl.X509TrustManagerFinder.findX509TrustManager;

class LocalOnlyTrustManager implements X509TrustManager {

  private X509TrustManager trustManager;

  LocalOnlyTrustManager(KeyStore localTrustStore) {
    try {
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(getDefaultAlgorithm());
      tmf.init(localTrustStore);

      trustManager = findX509TrustManager(tmf);
    }
    catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    trustManager.checkClientTrusted(chain, authType);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    trustManager.checkServerTrusted(chain, authType);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return trustManager.getAcceptedIssuers();
  }
}
