FROM rust-ubuntu22_04
#RUN apt install -y perl-ExtUtils-Embed
VOLUME /root/build
CMD cd /root/build && ../source/configure --with-defaults --disable-agent --disable-applications && make && make installheaders installlibs install_pkgconfig && tar -cvzf netsnmp_si-ubuntu22_04.tar.gz /usr/local/lib/libnetsnmp* && tar -cvzf netsnmp_si-ubuntu22_04-dev.tar.gz /usr/local/include/net-snmp /usr/local/lib/pkgconfig
