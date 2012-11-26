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

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

import static java.util.Arrays.asList;

public class LocalSslContext {

  private SSLContext delegate;
  private TrustManager[] trustManagers;

  public LocalSslContext(String protocol) throws NoSuchAlgorithmException {
    delegate = SSLContext.getInstance(protocol);
  }

  public void init(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) throws KeyManagementException {
    this.trustManagers = trustManagers;
    this.delegate.init(keyManagers, trustManagers, secureRandom);
  }

  public SSLSocketFactory getSocketFactory() {
    return delegate.getSocketFactory();
  }

  public String getProtocol() {
    return delegate.getProtocol();
  }

  public List<TrustManager> getTrustManagers() {
    return asList(trustManagers);
  }
}
