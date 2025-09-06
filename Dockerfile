FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y python3 python3-pip libpcap-dev libdumbnet-dev wget build-essential autoconf automake libtool
# Note: compiling Honeyd inside docker may require additional tweaks and privileged network capabilities.
# Copy honeyd binary if you have one; otherwise compile during build (not included here).
COPY honeyd.conf /etc/honeyd/honeyd.conf
COPY honeypot_scripts/ /usr/local/honeypot/scripts/
RUN chmod +x /usr/local/honeypot/scripts/*.py || true
EXPOSE 22 80 21 53 443
CMD ["/usr/sbin/honeyd","-f","/etc/honeyd/honeyd.conf","-d"]
