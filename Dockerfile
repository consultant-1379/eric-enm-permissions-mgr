ARG BUILD_DATE=unspecified
ARG IMAGE_BUILD_VERSION=unspecified
ARG GIT_COMMIT=unspecified
ARG ISO_VERSION=unspecified
ARG RSTATE=unspecified
ARG OS_BASE_IMAGE_NAME
ARG OS_BASE_IMAGE_REPO
ARG OS_BASE_IMAGE_TAG
ARG SGUSER=254222

FROM ${OS_BASE_IMAGE_REPO}/${OS_BASE_IMAGE_NAME}:${OS_BASE_IMAGE_TAG} as base
ARG SLES_BASE_OS_REPO="sles_base_os_repo"
ARG CBO_REPO=arm.rnd.ki.sw.ericsson.se/artifactory/proj-ldc-repo-rpm-local/common_base_os/sles/
ARG OS_BASE_IMAGE_TAG

ARG GCC_REPO=arm.sero.gic.ericsson.se/artifactory/proj-ldc-repo-rpm-local/adp-dev/go-sdk/
ARG GCC_VERSION="6.3.0-9"

WORKDIR /
RUN zypper addrepo -C -G -f https://${CBO_REPO}${OS_BASE_IMAGE_TAG}?ssl_verify=no $SLES_BASE_OS_REPO
RUN zypper addrepo -C -G -f https://arm.sero.gic.ericsson.se/artifactory/proj-ldc-repo-rpm-local/adp-dev/go-sdk/5.9.0-24?ssl_verify=no go-sdk
RUN zypper install -y curl python3 python3-pip libcap-progs && \
    python3 -m pip install pyOpenSSL kubernetes lxml xmltodict

FROM base as build_image
RUN command  zypper install -y gcc python3-devel python3-Cython && \
    zypper clean -a
COPY --chown=root:root ./rpm/src/permissions_change_module /permissions_change_module
COPY --chown=root:root ./rpm/src/permissions_script.py /permissions_script.py
WORKDIR /permissions_change_module
RUN python3 setup.py build_ext --inplace
WORKDIR /
RUN cython --embed -o permissions_script.c /permissions_script.py
RUN gcc -Os -I /usr/include/python3.6m -o permissions_script permissions_script.c -lpython3.6m -lpthread -lm -lutil -ldl

FROM base as result
LABEL \
com.ericsson.product-number="CXC Placeholder" \
com.ericsson.product-revision=$RSTATE \
enm_iso_version=$ISO_VERSION \
org.opencontainers.image.title="cENM permissions manager job" \
org.opencontainers.image.created=$BUILD_DATE \
org.opencontainers.image.revision=$GIT_COMMIT \
org.opencontainers.image.vendor="Ericsson" \
org.opencontainers.image.version=$IMAGE_BUILD_VERSION

COPY --from=build_image --chown=root:root /permissions_change_module /permissions_change_module
COPY --from=build_image --chown=root:root /permissions_script /permissions_script
COPY --from=build_image /usr/include /usr/include
COPY --chown=root:root ./rpm/data/pom.xml /pom.xml
COPY --chown=root:root ./rpm/data/pom2.xml /pom2.xml

USER root
RUN chmod 555 /permissions_script && \
    setcap cap_chown=ep /permissions_script && \
    cp /permissions_script /permissions_script2 && \
    cp /permissions_script /permissions_script_root_squash && \
    chmod u+s,g+s /permissions_script2 && \
    setcap cap_chown=ep /permissions_script && \
    chmod u+s /usr/bin/chown && \
    chmod u+s /usr/bin/mkdir && \
    setcap cap_chown=ep /usr/bin/chown && \
    zypper remove -y libcap-progs && \
    zypper clean -a && \
    echo "$SGUSER:x:$SGUSER:0: An Identity for permissions_mgr:/nonexistent:/bin/false" >>/etc/passwd && \
    echo "$SGUSER:!::0:::::" >>/etc/shadow && \
    rm -rf srv opt mnt root && \
    rm -rf run tmp /usr/share && \
    find /usr/bin/* -not -path /usr/bin/mkdir -not -path /usr/bin/rm -not -path /usr/bin/chmod -not -path /usr/bin/chown -not -path /usr/bin/id -exec rm -rf {} \; && \
    rm -rf /usr/bin/rm

USER $SGUSER
ENTRYPOINT ["./permissions_script_root_squash"]
