# Local SSL Context and TrustManager

Configurable trust manager to check HTTPS/SSL connections.

## Description

The LocalSslContext helps creating SSL connections with individual (self signed or non default) certificates or enables
the extension of the systems's default trust managers. You may also use this library in Android apps by using
a BKS typed KeyStore.


## Usage

#### Initialization
You need a keystore containing your trusted certificates:

    char[] passwordOrNull = null;
    InputStream trustStore = getClass().getClassLoader().getResourceAsStream("trustedCertificates.jks");
    sslContextFactory = new LocalSslContextFactory(trustStore, "JKS", passwordOrNull);
    ...

On Android you would use a BKS keystore from your raw resources:

    char[] passwordOrNull = null;
    InputStream trustStore = context.getResources().openRawResource(org.hypoport.ssl.R.raw.truststore);
    sslContextFactory = new LocalSslContextFactory(trustStore, "BKS", passwordOrNull);
    ...

#### Configuring your HTTPS connection
With the help of the LocalSslContextFactory you can create a TrustManager which uses only your trustStore:

    ...
    // example1: TrustManager using your individual trustStore only:
    LocalSslContext sslContextLocalOnly = sslContextFactory.createSslContextWithLocalOnlyTrustManager();
    httpsURLConnection.setSSLSocketFactory(sslContextLocalOnly.getSocketFactory());

You may also need a TrustManager which additionally uses the default trust managers:

    ...
    // example 2: TrustManager using your individual trustStore and all default trusted certificates:
    LocalSslContext sslContextLocalAndDefault = sslContextFactory.createSslContextWithLocalAndDefaultTrustManager();
    httpsURLConnection.setSSLSocketFactory(sslContextLocalAndDefault.getSocketFactory());

#### Android spezific keystores
A BKS keystore can easily be created with the help of [Portecle](http://portecle.sourceforge.net/). Loading BKS keystores needs a [BouncyCastle](http://www.bouncycastle.org/) provider, which is available as Maven artifact for non-Android systems:

    <!-- scope 'provided', because Android systems already use BKS as default provider -->
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk16</artifactId>
      <version>1.46</version>
      <scope>provided</scope>
    </dependency>


## Contributors
- [Tobias Gesellchen](https://github.com/gesellix)


## License
     Copyright 2012 HYPOPORT AG

     Licensed under the Apache License, Version 2.0 (the "License");
     you may not use this file except in compliance with the License.
     You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

     Unless required by applicable law or agreed to in writing, software
     distributed under the License is distributed on an "AS IS" BASIS,
     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     See the License for the specific language governing permissions and
     limitations under the License.
