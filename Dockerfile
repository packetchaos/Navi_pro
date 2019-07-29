FROM ubuntu:latest

RUN apt-get update && apt-get install -y python3-pip && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
	&& localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
RUN pip3 install requests && pip3 install click

ENV LANG en_US.utf8

CMD mkdir /usr/src/app

ADD Navi_pro.py /usr/src/app/

RUN ["chmod", "+x", "/usr/src/app/Navi_pro.py"]

ENV PATH "$PATH:/usr/bin/env/:/usr/src/app"

EXPOSE 8000

WORKDIR /usr/src/app