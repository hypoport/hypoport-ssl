FROM ubuntu:14.04
MAINTAINER Hypoport AG

RUN apt-get update && apt-get -y install openssl curl openjdk-7-jre-headless
ADD ./bcprov.jar /usr/lib/jvm/java-7-openjdk-amd64/jre/lib/ext/bcprov.jar

WORKDIR /certs
ADD ./create-certificates.sh /certs/create-certificates.sh
RUN /certs/create-certificates.sh
RUN keytool -import -file serverCA.crt -alias serverCA -keystore serverCA.bks -storetype BKS -provider org.bouncycastle.jce.provider.BouncyCastleProvider -storepass changeit -noprompt -keypass changeit

CMD ["ls", "-l"]
