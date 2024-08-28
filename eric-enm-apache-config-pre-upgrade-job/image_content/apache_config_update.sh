#!/bin/bash
#------------------------------------------------------------------------
#
#
#       COPYRIGHT (C) 2023                  ERICSSON AB, Sweden
#
#       The  copyright  to  the document(s) herein  is  the property of
#       Ericsson Radio Systems AB, Sweden.
#
#       The document(s) may be used  and/or copied only with the written
#       permission from Ericsson Radio Systems AB  or in accordance with
#       the terms  and conditions  stipulated in the  agreement/contract
#       under which the document(s) have been supplied.
#
#------------------------------------------------------------------------
KUBECTL=kubectl
KUBECTL_EXEC="${KUBECTL} exec -it"
GREP=grep
SED="sed -i"
AWK=awk
ECHO=echo

HTTPD_CONF=/etc/httpd/conf/httpd.conf
FTSSO_MAIN_KVM_CONF=/etc/httpd/conf.d/40_ftsso_main_kvm.conf
APACHE_CTL_RESTART="/usr/sbin/apachectl -d /etc/httpd/ -f conf/httpd.conf -k restart"
SERVICE_GROUPS=(cmutilities uiserv netex flsserv lcmserv impexpserv pmserv fileaccessnbi accesscontrol secserv websps saserv netsecserv nedoserv ipsmserv wpserv apserv nodecli pkiraserv fmhistory cellserv nodeplugins flowautomation nbalarmirp1 nbalarmirp2 ebscontroller nbfmsnmp sevserv)

for SG in "${SERVICE_GROUPS[@]}"
do
    for APP in `${KUBECTL} get pod | ${GREP} "^${SG}" | ${GREP} "Running" | ${AWK} '{print $1}'`
    do
        APACHE_RESTART=false
        GROUP=${SG}
        KUBECTL_GET="${KUBECTL} get pod ${APP} -o jsonpath='{.spec.containers[*].name}'"
        for CONTAINERS in `${KUBECTL_GET}`
        do
           if [[ ${CONTAINERS} == *"-httpd"* ]]
           then
               GROUP=${SG}-httpd
               break
           fi
        done
        ${KUBECTL_EXEC} ${APP} -c ${GROUP}  -- env | ${GREP} "^portHTTP="
        if [ $? == 1 ]
        then
            # Check if Listen 8084 is already in the httpd.conf
            ${KUBECTL_EXEC} ${APP} -c ${GROUP} -- ${GREP} "Listen 8084" ${HTTPD_CONF}
            if [ $? == 1 ]
            then
                ${ECHO} "Updating ${HTTPD_CONF} with Listen 8084 on ${APP}"

                ${KUBECTL_EXEC} ${APP} -c ${GROUP} -- ${SED} '/Listen ${portHTTP}/i Listen 8084' ${HTTPD_CONF}
                APACHE_RESTART=true
            fi
        fi

        ${KUBECTL_EXEC} ${APP} -c ${GROUP} -- env | ${GREP} -e "^AGENT_PORT="
        if [ $? == 1 ]
        then
            # Check if Listen is already in the httpd.conf
            ${KUBECTL_EXEC} ${APP} -c ${GROUP} -- ${GREP} "Listen 8444" ${HTTPD_CONF}
            if [ $? == 1 ]
            then
                ${ECHO} "Updating ${HTTPD_CONF} with Listen 8444 on ${APP}"

                ${KUBECTL_EXEC} ${APP} -c ${GROUP} -- ${SED} '/Listen ${portHTTP}/i Listen 8444' ${HTTPD_CONF}
                APACHE_RESTART=true
            fi

            ${KUBECTL_EXEC} ${APP} -c ${GROUP} -- ${GREP} "${APP}:8444" ${FTSSO_MAIN_KVM_CONF}
            if [ $? == 1 ]
            then
                ${ECHO} "Updating ${FTSSO_MAIN_KVM_CONF} with new HTTPS port on ${APP}"
                ${KUBECTL_EXEC} ${APP} -c ${GROUP} -- ${SED} 's/443>$/443 '${APP}':8444>/' ${FTSSO_MAIN_KVM_CONF}
                APACHE_RESTART=true
            fi
        fi
        if $APACHE_RESTART
        then
            ${ECHO} "Restarting Apache on ${APP} to apply temporary configuration"
            ${KUBECTL_EXEC} ${APP} -c ${GROUP} -- /bin/sh ${APACHE_CTL_RESTART}
        fi
    done
done
