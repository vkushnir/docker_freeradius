FROM ubuntu:16.04 as build

COPY include/localtime /etc/

RUN apt-get update
RUN apt-get install -y build-essential ca-certificates git libtool vim wget \
    fakeroot dpkg-dev quilt debhelper mc
RUN apt-get install -y libcurl4-openssl-dev libcap-dev libgdbm-dev \
    libiodbc2-dev libjson0-dev libkrb5-dev libldap2-dev libpam0g-dev \
    libpcap-dev libperl-dev libmysqlclient-dev libpq-dev libreadline-dev \
    libsasl2-dev libsqlite3-dev libssl-dev libtalloc-dev libwbclient-dev \
    libyubikey-dev libykclient-dev libmemcached-dev libhiredis-dev python-dev \
    samba-dev libcollectdclient-dev
RUN apt-get install -y snmp tcpdump sqlite

ARG FREERADIUS_VER=2.2.10
ARG FREERADIUS_URL=ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-${FREERADIUS_VER}.tar.gz
ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /usr/src/
RUN wget ${FREERADIUS_URL}
RUN tar zxf freeradius-server-${FREERADIUS_VER}.tar.gz

WORKDIR /usr/src/freeradius-server-${FREERADIUS_VER}
RUN cp /usr/share/libtool/build-aux/missing .
RUN ./configure \
      --with-oracle-include-dir=/usr/include/oracle/$ORACLE_INSTANTCLIENT_MAJOR/client64 \
      --with-oracle-lib-dir=/usr/lib/oracle/$ORACLE_INSTANTCLIENT_MAJOR/client64/lib
RUN make
RUN cd src/modules/rlm_sql/drivers/rlm_sql_oracle
RUN make install

FROM vkushnir/oracle-instantclient as runtime

ARG DEBIAN_FRONTEND=noninteractive
ARG FREERADIUS_VER=2.2.8

ENV FREERADIUS_VERSION ${FREERADIUS_VER}
ENV RADIUS_NAME="freeradius"
ENV RADIUS_USER="freerad"
ENV RADIUS_GROUP="freerad"
ENV RADIUS_UID="105"
ENV RADIUS_GID="107"

WORKDIR /

RUN apt-get update \
 && apt-get install -y freeradius freeradius-mysql snmp tcpdump \ 
 && apt-get autoremove \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/lib/rlm_sql_oracle.* /usr/lib/freeradius/
COPY include/localtime /etc
COPY include/entrypoint.sh /usr/bin/

EXPOSE 1812/udp 1813/udp

VOLUME /opt/freeradius
VOLUME /var/log/freeradius

ENTRYPOINT ["entrypoint.sh"]
CMD ["-f"]

