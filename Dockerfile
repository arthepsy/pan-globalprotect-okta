FROM alpine:3.8

WORKDIR /

RUN apk add -U openssl openssl-dev bash curl tar wget nano build-base ca-certificates automake gcc abuild binutils \
 && apk add python openssh-client libtool intltool autoconf libxml2-dev krb5-dev lz4 lz4-dev linux-headers py2-lxml py2-requests	git \
 && rm -rf /var/cache/apk/*

RUN git clone https://github.com/dlenski/openconnect.git
RUN mkdir -p /usr/local/sbin
RUN wget http://git.infradead.org/users/dwmw2/vpnc-scripts.git/blob_plain/HEAD:/vpnc-script -O /usr/local/sbin/vpnc-script
ADD vpnc-script-os /usr/local/sbin/vpnc-script
RUN chmod +x /usr/local/sbin/vpnc-script

WORKDIR /openconnect

RUN ./autogen.sh
RUN ./configure --with-vpnc-script=/usr/local/bin/vpnc-script
RUN make check
RUN make

CMD ["/openconnect/gp-okta/gp-okta.py", "/openconnect/gp-okta/gp-okta.conf"]