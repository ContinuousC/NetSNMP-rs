FROM rust-rhel8
RUN yum install -y perl-ExtUtils-Embed && yum clean all
VOLUME /root/build
CMD cd /root/build && ../source/configure --with-defaults --disable-agent --disable-applications && make && make installheaders installlibs install_pkgconfig && tar -cvzf netsnmp_si-rhel8.tar.gz /usr/local/lib/libnetsnmp* && tar -cvzf netsnmp_si-rhel8-dev.tar.gz /usr/local/include/net-snmp /usr/local/lib/pkgconfig
