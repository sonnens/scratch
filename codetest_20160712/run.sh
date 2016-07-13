#!/bin/sh

PATH=/opt/nodejs/current/bin:$PATH

cd $(dirname $0)

touch server.log
chown www-data:www-data server.log
chmod 600 server.log

/opt/nodejs/current/bin/node main.js
