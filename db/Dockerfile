# Filename: Database

# Base Image
FROM mysql:5.7

# Update
RUN apt-get -y update
RUN apt-get -y install vim nano

# Setup SQL environment
ENV MYSQL_USER: root
ENV MYSQL_PASSWORD: password
ENV MYSQL_ROOT_PASSWORD: password
ENV MYSQL_DATABASE: auth

EXPOSE 3306

ADD . .

CMD mysql -u $MYSQL_USER -p $MYSQL_PASSWORD $MYSQL_DATABASE < init.sql