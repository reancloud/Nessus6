#!/bin/sh

#
# Script looks for target files in incoming directory, and launches Nessus
#

BASEDIR=/opt/scanner
TEMPDIR=${BASEDIR}/temp$$
INCOMINGDIR=${BASEDIR}/targets/incoming
RESULTSDIR=${BASEDIR}/results
SENDMAIL="/usr/lib/sendmail -t"

NESSUSBIN=/opt/nessus/bin/nessus
NESSUSUSER=xxxx
NESSUSPASSWORD=XXXXXXXXXXXXXXX

APPENDRESULTS="x-scanner|${IPADDR}"

mkdir -p ${TEMPDIR}

#
# Grab one file in incoming directory
#
FILES=`cd ${INCOMINGDIR}; ls -r -1 *.txt | tail -n 1`
for file in $FILES
do
  echo "Moving ${INCOMINGDIR}/${file} to ${TEMPDIR}/${file}..."
  cp ${INCOMINGDIR}/${file} ${BASEDIR}/targets/archive/${file}
  mv ${INCOMINGDIR}/${file} ${TEMPDIR}/${file}
  if [ $? -eq 0 ]
  then
    #
    # Find request id
    #
    REQUESTID=`cat ${TEMPDIR}/${file} | grep "requestid" | awk '{ print $2 }'`
    if [ -z ${REQUESTID} ]
    then
      REQUESTID=`date -u +%s`
    else
      APPENDRESULTS="${APPENDRESULTS}
x-requestid|${REQUESTID}"
    fi

    #
    # Find scanning method and nessusrc
    #
    METHOD=`cat ${TEMPDIR}/${file} | grep "method" | awk '{ print $2 }'`
    if [ -z ${METHOD} ]
    then
      METHOD="default"
    fi

    #    NESSUSRC="${NESSUSRC}.${METHOD}"
    NESSUSRC="${BASEDIR}/${METHOD}.nessusrc"

    #
    # Create target file
    #
    TARGETFILE=${TEMPDIR}/tmp_target_${IPADDR}_${REQUESTID}.txt
    RESULTSFILE=${TEMPDIR}/results_${IPADDR}_${REQUESTID}_$$.nbe
    echo "Creating ${TARGETFILE}..."
    cat ${TEMPDIR}/${file} | grep "\/" > ${TARGETFILE}

    #
    # Launch Nessus
    #
    echo "Launching Nessus..."
    ${NESSUSBIN} -x -q -c ${NESSUSRC} 127.0.0.1 1241 ${NESSUSUSER} ${NESSUSPASSWORD} ${TARGETFILE} ${RESULTSFILE}
    if [ $? -eq 0 ] && [ -s ${RESULTSFILE} ]
    then
      echo "${APPENDRESULTS}" >> ${RESULTSFILE}
    else
      # Nessus failed, move target file back to incoming dir
      mv ${TEMPDIR}/${file} ${INCOMINGDIR}/${file}
      rm -rf ${TEMPDIR}
      exit 1
    fi

    echo "Moving ${RESULTSFILE} to ${RESULTSDIR}..."

    # copy results to results dir
    cp ${RESULTSFILE} ${BASEDIR}/archive
    mv ${RESULTSFILE} ${RESULTSDIR}/
    echo "Cleaning up ${TEMPDIR}..."
    rm ${TARGETFILE} ${TEMPDIR}/${file}
  fi
done

rmdir --ignore-fail-on-non-empty ${TEMPDIR}
