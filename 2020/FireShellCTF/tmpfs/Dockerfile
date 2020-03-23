FROM ubuntu:18.04

RUN apt-get update
# RUN apt-get upgrade -y
RUN apt-get install xinetd libseccomp-dev python \
    python-pip wget libbsd-dev gdb -y

RUN pip install --upgrade pip
RUN pip install pwntools
RUN wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh

RUN useradd -m tmpfs

ADD --chown=root:root ./client /home/tmpfs/
ADD --chown=root:root ./server /home/tmpfs/
ADD --chown=root:root ./run.sh /home/tmpfs/
ADD --chown=root:root ./flag /
ADD --chown=root:root xinetd /etc/xinetd.d/tmpfs

RUN chmod +x /home/tmpfs/run.sh
RUN chmod +x /home/tmpfs/client
RUN chmod +x /home/tmpfs/server

RUN chmod 744 /tmp
RUN chmod -R 774 /var/tmp
RUN chmod -R 774 /dev
RUN chmod -R 774 /run
RUN chmod 1733 /tmp /var/tmp /dev/shm

RUN chown -R root:root /home/tmpfs/

EXPOSE 30047/tcp

CMD ["/usr/sbin/xinetd", "-dontfork"]

