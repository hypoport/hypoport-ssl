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

import org.testng.annotations.Test;

import javax.net.ssl.X509TrustManager;

@Test
public class LocalSslContextFactoryLocalAndDefaultTrustManagerTest extends LocalSslContextFactoryTest {

  @Override
  protected LocalSslContext createSslContext() {
    return sslContextFactory.createSslContextWithLocalAndDefaultTrustManager();
  }

  @Override
  protected Class<? extends X509TrustManager> getTrustManagerType() {
    return LocalAndDefaultTrustManager.class;
  }
}
