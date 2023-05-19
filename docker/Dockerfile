FROM snisioi/retele:2021

RUN apt-get update && apt-get install -y iptables iproute2 libnetfilter-queue-dev

RUN pip3 install --upgrade python-iptables cython

RUN mkdir -p /scripts
RUN mkdir -p /pyscripts
RUN mkdir -p /dns

COPY src/*.sh /scripts/
COPY src/*.py /pyscripts/

COPY src/DNS.py /dns/
COPY src/data /dns/data

