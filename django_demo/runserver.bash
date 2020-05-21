#!/bin/bash 

# Script to kill previous instances of dev servers,
# then start the 2 dev servers, one of which is https.
#
# Calling the https server should be done with https://localhost:8443/

cd "$(dirname "$0")"
echo $PWD

. bin/activate
kill -15 `ps -ef | egrep 'bin.python manage.py runserver 8006' | grep -v grep | awk '{ print $3}'`
kill -15 `ps -ef | egrep 'bin.python manage.py runserver 8001' | grep -v grep | awk '{ print $3}'`
if [[ -z `ps -ef | egrep 'stunnel4 stunnel/dev_https' | grep -v grep | awk '{ print $3}'` ]]; then
    stunnel4 stunnel/dev_https &
fi
python manage.py runserver 8006 &
HTTPS=1 python manage.py runserver 8001
