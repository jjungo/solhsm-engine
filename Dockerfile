FROM ubuntu:14.04.3

MAINTAINER Joel Jungo <j.jungo@gmail.com>

RUN     apt-get update && apt-get upgrade -y \
        && apt-get install git stunnel apache2 -y

RUN     cp /usr/share/zoneinfo/Europe/Zurich /etc/localtime \
        && echo "Europe/Zurich" > /etc/timezone

RUN     make && make install

RUN     cd ./tools/ \
        && make \
        && ./generate_cert client \
        && mkdir -p /root/keys/{pub,priv} \
        && cp client.cert_secret /root/keys/priv/ \
        && cp client.cert /root/keys/

COPY    apache.conf /etc/stunnel/stunnel.conf
ADD     run.sh /usr/bin/run
RUN     chmod +x /usr/bin/run \
        && echo  " \
<h2>Welcome to solhsm web server</h2> \
<p>This is only a test page.</p> \
"        > /var/www/html/index.html

EXPOSE  443 80

RUN     echo "DO NOT forget to share your public key with your HSM"

CMD ["/usr/bin/run"]
