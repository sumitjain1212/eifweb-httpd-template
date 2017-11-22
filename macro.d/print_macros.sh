#!/bin/bash

declare -x SED="/usr/bin/sed"
declare -x DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [[ "$(uname)" == "Darwin" ]]; then
    if [[ -e /usr/local/bin/gsed ]]; then
        SED=/usr/local/bin/gsed
    else
        echo "No Gnu sed found, exit"
        exit 1
    fi
fi

echo -e '#----------------------------------------------------------------#'
echo -e "# variables"
echo -e '#----------------------------------------------------------------#\n'
cat <<'HERE' | sed 's/^/# /g'
<DOCROOT> is /auto/my/docroot or ${EIF_VH_DOCROOT..}/app
<PROXY1_HOSTPORT> is sjc-aspl-tc1.cisco.com:8081
<PROXY1_NAME> is app_1_0
<PROXY1_PROTOHOSTPORT> is http://sjc-aspl-py1:9012/
<PROXY_PATH> is / or /api/
<SSO_LOCATION> is / or /protected/
<URL_FQDN> is wwwin-app.cisco.com
<URL_SHORT> is wwwin-app
<URL_TARGET> is https://wwwin-new-app.cisco.com/
<WEBMASTER> is webmaster-app@cisco.com
HERE
echo -e "\n"


(
    cd "${DIR}"
    F=virtual_servers_macro.conf
    echo -e '#----------------------------------------------------------------#'
    echo -e "# ${F}"
    echo -e '#----------------------------------------------------------------#\n'
    ${SED} -n  's/<Macro\s\+\(MACRO_[^>]\+\)>\s*$/\1/p' ${F} | sed 's/\${MACRO_VH_/</g' | sed 's/\}/>/g' | sort -u -k1,1 | sed 's/^/# Use /g'
    echo -e "\n"

    F=virtual_servers_ssl_macro.conf
    echo -e '#----------------------------------------------------------------#'
    echo -e "# ${F}"
    echo -e '#----------------------------------------------------------------#\n'
    ${SED} -n  's/<Macro\s\+\(MACRO_[^>]\+\)>\s*$/\1/p' ${F} | sed 's/\${MACRO_VH_/</g' | sed 's/\}/>/g' | sort -u -k1,1 | sed 's/^/# Use /g'
    echo -e "\n"

)
