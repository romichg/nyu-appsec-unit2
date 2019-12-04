FROM debian:latest
MAINTAINER RomichG hello@romich-g.com

#Update packages
RUN apt-get update 
RUN DEBIAN_FRONTEND=noninteractive apt-get -y upgrade


#Install prereq 
RUN DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install python3 python3-pip python3-setuptools sqlite3 git

#Clone my repo 
RUN git clone https://github.com/romichg/nyu-appsec-unit2

#Install requirements
RUN cd nyu-appsec-unit2 \
        && pip3 install -r ./requirements.txt

EXPOSE 8080
WORKDIR nyu-appsec-unit2
ENTRYPOINT [ "flask",  "run", "--host=0.0.0.0", "--port=8080" ]
