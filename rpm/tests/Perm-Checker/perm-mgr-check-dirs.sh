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
CAT=/usr/bin/cat
MV=mv
RESULT="Passed"

if [ ! -f local_pom.xml ]
then
    echo "File local_pom.xml does not exist"
    echo "local_pom.xml needs to be in same directory"
    exit 1
fi

ALL_DIRS=ALLDirs.txt
THE_TEMP=tempResults.txt

[ -e ${ALL_DIRS} ] && rm ${ALL_DIRS}
[ -e ${THE_TEMP} ] && rm ${THE_TEMP}

${AWK} -F'[<>]' '/create_directories/ { print $3 }' local_pom.xml | tr "," "\n" > ${ALL_DIRS}
[ -s ${ALL_DIRS} ] && ${ECHO} "---- Directories collected from local_pom.xml" || exit 1

${ECHO} "---- First collect the directories that exist on omnidaemon "

# Collect alex directories using omnidaemon
ONMI=`${KUBECTL} get pod | ${GREP} "^omnidaemon" | ${GREP} "Running" | ${AWK} '{print $1}'`

${KUBECTL_EXEC} ${ONMI} -- bash -c "ls -ld /ericsson/enm/alex/libraries" | grep alex > tempResults.txt 2>&1
${KUBECTL_EXEC} ${ONMI} -- bash -c "ls -ld /ericsson/enm/alex/writable" | grep alex >> tempResults.txt 2>&1

# Remove lines not needed.
${SED} '/alex/d' ${ALL_DIRS} 
${SED} '/Defaulted/d' tempResults.txt
# Remove /ericsson/tor/dat/apps its not non root till all httpds are delivered.
${SED} '/apps/d' ${ALL_DIRS}

# Collect jms directories using jms

${ECHO} "---- Collect the directories that exist on jms "
JMS=`${KUBECTL} get pod | ${GREP} "^jms" | ${GREP} "Running" | ${AWK} '{print $1}'`
${ECHO} ${JMS}

${KUBECTL_EXEC} ${JMS} -- bash -c "ls -ld /ericsson/jms/log /ericsson/jms/data /ericsson/jms/data/eap7" | grep jms >> tempResults.txt 2>&1
${KUBECTL_EXEC} ${JMS} -- bash -c "ls -ld /ericsson/jms/data/eap7/bindings /ericsson/jms/data/eap7/journal /ericsson/jms/data/eap7/large-messages" | grep jms >> tempResults.txt 2>&1
${SED} '/jms/d' ${ALL_DIRS}

SERVICE_GROUPS=(rwxpvc)

for SG in "${SERVICE_GROUPS[@]}"
do
    for APP in `${KUBECTL} get pod | ${GREP} "^${SG}" | ${GREP} "Running" | ${AWK} '{print $1}'`
    do
	${ECHO} " ---- Using ${APP} to collect directory status now ----"
        ${KUBECTL} cp ${ALL_DIRS} ${APP}:/var/tmp/${ALL_DIRS} 2>&1
        if [ $? == 0 ]
        then
	    ${KUBECTL_EXEC} ${APP} -- bash -c "cat /var/tmp/${ALL_DIRS} | xargs ls -ld 2>/dev/null" >> tempResults.txt 2>&1
            ${SED} '/Defaulted/d' tempResults.txt
        else
	    ${ECHO} "Something went wrong with the copy to ${APP}"
	fi
        ${CAT} tempResults.txt | awk '{ print $1 " " $3 " " $4 "\t\t " $NF}' >> DirCheck-Result_$(date +"%FT%H%M").log 2>&1
    done
done
# Check the results
${ECHO} -e "\nTHE RESULTS"
${ECHO} -e "----------------------------------" 
${GREP} -e "^drwx-" -e "^drwxr-" -e "^drwxrw-" -e "^dr-xr-s" -e "^drwxr-s" -e "^d-" -e "^dr-" -e "^drw-" tempResults.txt
if [ $? == 0 ]
then
   RESULT="Failed"
   ${ECHO} "WARNING: WRONG rwx permissions in results - check the log file DirCheck-Result_$(date +"%FT%H%M").log"
fi
# Check the owner and group is not root
${GREP} " root " tempResults.txt
if [ $? == 0 ]
then
   RESULT="Failed"
   ${ECHO} "WARNING: WRONG owner or group in results - check the log file DirCheck-Result_$(date +"%FT%H%M").log "
fi

# Create a results file 
${CAT} tempResults.txt | awk '{ print $1 " " $3 " " $4 "\t\t " $NF}' >> DirCheck-Result_$(date +"%FT%H%M").log 2>&1
if [ $RESULT == "Failed" ]
then
   ${ECHO} -e "\n================================"
   ${ECHO} -e "\nWARNING: Test Result is failed"
   ${ECHO} -e "\n================================"
   ${ECHO} -e "\nWARNING: Test Result is failed" >> DirCheck-Result_$(date +"%FT%H%M").log 2>&1
   ${GREP} -e "^drwx-" -e "^drwxr-" -e "^drwxrw-" -e "^dr-xr-s" -e "^drwxr-s" -e "^d-" -e "^dr-" -e "^drw-" tempResults.txt | sort -u >> DirCheck-Result_$(date +"%FT%H%M").log 2>&1
   ${GREP} " root " tempResults.txt | sort -u >> DirCheck-Result_$(date +"%FT%H%M").log 2>&1
else
   ${ECHO} -e "\n================================"
   ${ECHO} -e "\nTest Result is Passed"
   ${ECHO} -e "\n================================"
   ${ECHO} -e "\nTest Result is Passed" >> DirCheck-Result_$(date +"%FT%H%M").log 2>&1
fi
${SED} '/command with exit/d' DirCheck-Result_$(date +"%FT%H%M").log
#${SED} -i 's/^M//g' DirCheck-Result_$(date +"%FT%H%M").log
${SED} -i 's/\r//g' DirCheck-Result_$(date +"%FT%H%M").log
