FROM debian:stable-slim
LABEL maintainer="Stegen Smith <stegen@owns.com>"

ENV HEALTCHECK_HOST $HEALTHCHECK_HOST

WORKDIR /vpn

ADD scripts/run.sh run.sh

ADD gp-okta.py .
ADD gp-okta.conf .
ADD requirements.txt .

RUN ln -fs /usr/share/zoneinfo/America/Los_Angeles /etc/localtime

RUN apt-get update && apt-get -y install bash curl iproute2 iptables iputils-ping \
    less mtr net-tools openconnect procps python3-pip strace tcpdump vim

RUN pip install -r requirements.txt

HEALTHCHECK  --interval=10s --timeout=10s --start-period=10s \
  CMD ping -c 3 $HEALTHCHECK_HOST

CMD ["/vpn/run.sh"]
