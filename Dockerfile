FROM alpine:3.7

WORKDIR /

RUN apk add -U openssl openssl-dev bash curl tar wget nano build-base ca-certificates automake gcc abuild binutils \
 && apk add python openssh-client libtool intltool autoconf libxml2-dev krb5-dev lz4 lz4-dev linux-headers py2-lxml py2-requests	git \
 && rm -rf /var/cache/apk/*

RUN apk add vpnc --update-cache --repository http://dl-3.alpinelinux.org/alpine/edge/testing/ --allow-untrusted


RUN git clone https://github.com/dlenski/openconnect.git
RUN mkdir -p /usr/local/sbin
ADD vpnc-script-os /usr/local/sbin/vpnc-script
RUN chmod +x /usr/local/sbin/vpnc-script

WORKDIR /openconnect

RUN ./autogen.sh
RUN ./configure
RUN make check
RUN make

CMD ["/openconnect/gp-okta/gp-okta.py", "/openconnect/gp-okta/gp-okta.conf"]