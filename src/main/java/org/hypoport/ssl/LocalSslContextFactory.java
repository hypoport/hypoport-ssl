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

import javax.net.ssl.TrustManager;
import java.io.InputStream;
import java.security.KeyStore;

public class LocalSslContextFactory {

  private final KeyStore trustStore;

  public LocalSslContextFactory(InputStream localTrustStore, String keyStoreType, char[] passwordOrNull) {
    trustStore = loadTrustStore(localTrustStore, keyStoreType, passwordOrNull);
  }

  public LocalSslContext createSslContextWithLocalOnlyTrustManager() {
    TrustManager localOnlyTrustManager = new LocalOnlyTrustManager(trustStore);
    TrustManager[] trustManagers = new TrustManager[] {localOnlyTrustManager};
    return createSslContext(trustManagers);
  }

  public LocalSslContext createSslContextWithLocalAndDefaultTrustManager() {
    TrustManager localAndDefaultTrustManager = new LocalAndDefaultTrustManager(trustStore);
    TrustManager[] trustManagers = new TrustManager[] {localAndDefaultTrustManager};
    return createSslContext(trustManagers);
  }

  private static KeyStore loadTrustStore(InputStream trustStore, String keyStoreType, char[] passwordOrNull) {
    try {
      KeyStore localTrustStore = KeyStore.getInstance(keyStoreType);
      localTrustStore.load(trustStore, passwordOrNull);
      return localTrustStore;
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static LocalSslContext createSslContext(TrustManager[] trustManagers) {
    try {
      LocalSslContext localSslContext = new LocalSslContext("TLSv1");
      localSslContext.init(null, trustManagers, null);
      return localSslContext;
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
