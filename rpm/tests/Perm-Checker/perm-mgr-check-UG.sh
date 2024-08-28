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
RESULT="Passed"

THE_DIRS=theDirs.txt
THE_CHANGES=Uprade-Changes_$(date +"%FT%H%M").log
THE_RESULT=Uprade-Result_$(date +"%FT%H%M").log
UG_TEMP=UGResults.txt
# We need a parmeter to know what to do
if [ "$#" -eq 0 ]; then
   echo "No arguments provided."
   echo "Use 'before' to set directories before an UG"
   echo "Use 'after' to check directories after the UG"
   exit 1
fi
# We need local_pom.xml to have directories 
if [ ! -f local_pom.xml ]
then
    echo "File local_pom.xml does not exist"
    echo "local_pom.xml needs to be in same directory"
    exit 1
fi


[ -e ${THE_DIRS} ] && rm ${THE_DIRS}
[ -e ${UG_TEMP} ] && rm ${UG_TEMP}

awk -F'[<>]' '/create_directories/ { print $3 }' local_pom.xml | tr "," "\n" > theDirs.txt
[ -s ${THE_DIRS} ] && ${ECHO} "---- Directories collected from local_pom.xml" || exit 1


if [ "$1" == "before" ]
then
   ${ECHO} "---- First change the directories" 
   SERVICE_GROUPS=(rwxpvc)
   for SG in "${SERVICE_GROUPS[@]}"
   do
    for APP in `${KUBECTL} get pod | ${GREP} "^${SG}" | ${GREP} "Running" | ${AWK} '{print $1}'`
    do
	${ECHO} " ---- Using ${APP} to change file and directory permissions and owners now ----"
        ${KUBECTL} cp changedirs.cmd ${APP}:/changedirs.cmd 2>&1
        if [ $? == 0 ]
        then
            ${ECHO} " ---- Using ${APP} to change file and directory permissions and owners now ----"
	    ${KUBECTL_EXEC} ${APP} -- bash -c "/changedirs.cmd" >> ${THE_CHANGES} 2>&1
            ${ECHO} -e "\n---- Changes made to file systems - check the log file called ${THE_CHANGES} \n"
        else
	    ${ECHO} "Something went wrong with the copy to ${APP}"
	fi
   done
  done
elif [ "$1" == "after" ]
then
   ${ECHO} "---- After the UG check the directories" >> ${THE_RESULT}
   SG=(rwxpvc)
   for APP in `${KUBECTL} get pod | ${GREP} "^${SG}" | ${GREP} "Running" | ${AWK} '{print $1}'`
   do
        ${ECHO} "---- Using ${APP} to check permissions and owners status now ----"
        ${KUBECTL} cp checkdirs.cmd ${APP}:/checkdirs.cmd 2>&1
        if [ $? == 0 ]
        then
            ${KUBECTL_EXEC} ${APP} -- bash -c "/checkdirs.cmd " >> ${THE_RESULT} 2>&1
        else
            ${ECHO} "Something went wrong with the copy to ${APP}"
        fi
        ${SED} -i 's/\r//g' ${THE_RESULT}
        ${ECHO} -e "\n ---- Now check all the direcories and files are still g=u  ----"
        ${GREP} -e "^drwx-" -e "^drwxr-" -e "^drwxrw-" -e "^dr-xr-s" -e "^drwxr-s" -e "^d-" -e "^dr-" -e "^drw-" ${THE_RESULT}
        if [ $? == 0 ]
        then
            RESULT="Failed"
            ${ECHO} -e "WARNING: r-x permissions in results - check the log file called ${THE_RESULT} \n\n"
        fi
        ${GREP} "cannot" ${THE_RESULT}
        if [ $? == 0 ]
        then
            RESULT="Failed"
            ${ECHO} -e "WARNING: Directories did not get created - check the log file called ${THE_RESULT} \n\n"
        fi
        ${GREP} "root " ${THE_RESULT}
        if [ $? == 0 ]
        then
            RESULT="Failed"
            ${ECHO} -e "WARNING: WRONG owner or group in results - check the log file called ${THE_RESULT} \n\n "
        fi
   done
   if [ $RESULT == "Failed" ]
   then
      ${ECHO} -e "\n================================"
      ${ECHO} -e "\nWARNING: Test Result is failed"
      ${ECHO} -e "\n================================"
      ${ECHO} -e "\nWARNING: Test Result is failed" >> ${THE_RESULT} 2>&1
   else
      ${ECHO} -e "\n================================"
      ${ECHO} -e "\nTest Result is Passed"
      ${ECHO} -e "\n================================"
      ${ECHO} -e "\nTest Result is Passed" >> ${THE_RESULT} 2>&1
   fi
else
  ${ECHO} "Something went wrong there ............"
  ${ECHO} "It needs before or after as a parameter"
fi
