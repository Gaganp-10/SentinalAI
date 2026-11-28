FROM postgres:15.20-alpine3.24

# Remediate Alpine libxml2 HIGH CVEs (2.13.9-r2 -> >= 2.13.9-r5) without upgrading unrelated packages
RUN apk upgrade --no-cache libxml2 \
    && LIBXML2_VER=$(apk info -e -v libxml2 | sed 's/^libxml2-//') \
    && echo "Installed libxml2 version: ${LIBXML2_VER}" \
    && CMP=$(apk version -t "${LIBXML2_VER}" "2.13.9-r5") \
    && test "${CMP}" = "=" -o "${CMP}" = ">"
