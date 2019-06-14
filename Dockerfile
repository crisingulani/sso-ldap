FROM python:3.6-alpine
COPY . /sso
WORKDIR /sso
RUN apk update && apk add build-base gcc python3-dev musl-dev libressl-dev openldap-dev 
RUN pip install -r requirements.txt
CMD ["/bin/sh"]