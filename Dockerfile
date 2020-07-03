FROM python:3.8.3-slim AS builder

WORKDIR	/

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl automake autoconf libtool make \
        libxml2-dev zlib1g-dev libssl-dev pkg-config

RUN curl -L -o /tmp/openconnect.tar.gz https://gitlab.com/openconnect/openconnect/-/archive/v8.10/openconnect-v8.10.tar.gz
RUN tar xvzf /tmp/openconnect.tar.gz
WORKDIR	/openconnect-v8.10
RUN	./autogen.sh
RUN	./configure --without-gnutls --disable-nls --with-vpnc-script=/usr/local/sbin/vpnc-script
RUN	make check
RUN	make
RUN make install

RUN curl -o /usr/local/sbin/vpnc-script https://gitlab.com/openconnect/vpnc-scripts/-/raw/master/vpnc-script
RUN	chmod +x /usr/local/sbin/vpnc-script

FROM python:3.8.3-slim

RUN pip install pyotp requests lxml
RUN set -x \
    && apt-get update \
    && apt-get install -y libxml2 net-tools \
    && apt-get clean
COPY --from=builder /usr/local /usr/local
RUN ldconfig

COPY gp-okta.py /usr/local/bin

CMD	["python", "-u", "/usr/local/bin/gp-okta.py", "/etc/gp-okta.conf"]
