#!/bin/bash
set -e

opt="/opt/${RADIUS_NAME}"
raddb="/etc/${RADIUS_NAME}"

RADIUS_UID_ACTUAL=$(id -u ${RADIUS_USER})
RADIUS_GID_ACTUAL=$(id -g ${RADIUS_GROUP})

#
# Change UID / GID of radius user.
#
echo 
echo "Updating UID / GID ..."
if [ ${RADIUS_GID_ACTUAL} -ne ${RADIUS_GID} -o ${RADIUS_UID_ACTUAL} -ne ${RADIUS_UID} ]
then
    echo "change user uid: ${RADIUS_UID_ACTUAL}->${RADIUS_UID} / group gid: ${RADIUS_GID_ACTUAL}->${RADIUS_GID}"
    usermod --uid ${RADIUS_UID} ${RADIUS_USER}
    groupmod --gid ${RADIUS_GID} ${RADIUS_GROUP}
    echo "[DONE]"
    echo "Set owner and permissions for old uid/gid files"
    find / -path /proc -prune -o -user ${RADIUS_UID_ACTUAL} -exec chown ${RADIUS_USER} {} \;
    find / -path /proc -prune -o -group ${RADIUS_GID_ACTUAL} -exec chgrp ${RADIUS_GROUP} {} \;
    echo "[DONE]"
else
    echo "[NOTHING DONE]"
fi
echo User: ${RADIUS_USER}, UID:${RADIUS_UID}
echo Group: ${RADIUS_GROUP}, GID:${RADIUS_GID}

#
# Update configuration files
#
echo
echo "Update configuration files"
cp -Rfv ${opt}/* ${raddb}/
echo "[DONE]"

#
# Start RADIUS Server
#
echo
echo "Starting RADIUS server ..."
/usr/sbin/${RADIUS_NAME} $@
echo "[DONE]"

