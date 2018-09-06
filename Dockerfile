FROM	alpine:3.8

WORKDIR	/

RUN	apk add --no-cache \
	curl git \
	automake autoconf libtool gcc musl-dev make linux-headers \
	gettext gnutls-dev libxml2-dev lz4-dev libproxy-dev \
	py2-lxml py2-requests py2-pip \
	&& rm -rf /var/cache/apk/*
RUN  pip install pyotp


RUN	mkdir -p /usr/local/sbin
RUN	curl -o /usr/local/sbin/vpnc-script http://git.infradead.org/users/dwmw2/vpnc-scripts.git/blob_plain/HEAD:/vpnc-script
RUN	chmod +x /usr/local/sbin/vpnc-script

RUN	git clone https://github.com/dlenski/openconnect.git
WORKDIR	/openconnect
RUN	./autogen.sh
RUN	./configure --with-vpnc-script=/usr/local/sbin/vpnc-script
RUN	make check
RUN	make

CMD	["/openconnect/gp-okta/gp-okta.py","/openconnect/gp-okta/gp-okta.conf"]
