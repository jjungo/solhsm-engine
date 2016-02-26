FROM jjungo/img-base:0.9a

MAINTAINER Joel Jungo <j.jungo@gmail.com>

RUN     apt-get update && apt-get upgrade -y \
        && apt-get install stunnel apache2 libssl-dev -y

RUN     cp /usr/share/zoneinfo/Europe/Zurich /etc/localtime \
        && echo "Europe/Zurich" > /etc/timezone

COPY    ./ /root/install/solhsm-engine
WORKDIR /root/install/solhsm-engine
RUN     make && make install

COPY    apache.conf /etc/stunnel/stunnel.conf
ADD     run.sh /usr/bin/run
RUN     chmod +x /usr/bin/run \
        && echo  " \
<h2>Welcome to solhsm web server</h2> \
<p>This is only a test page.</p> \
"        > /var/www/html/index.html

EXPOSE  443 80

WORKDIR /
RUN     echo "DO NOT forget to share your public key with your HSM"

CMD ["/usr/bin/run"]
