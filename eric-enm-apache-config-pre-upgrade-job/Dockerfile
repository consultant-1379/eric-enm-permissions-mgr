ARG ERIC_ENM_SLES_BASE_IMAGE_NAME=eric-enm-sles-base
ARG ERIC_ENM_SLES_BASE_IMAGE_REPO=armdocker.rnd.ericsson.se/proj-enm
ARG ERIC_ENM_SLES_BASE_IMAGE_TAG=1.64.0-28

FROM ${ERIC_ENM_SLES_BASE_IMAGE_REPO}/${ERIC_ENM_SLES_BASE_IMAGE_NAME}:${ERIC_ENM_SLES_BASE_IMAGE_TAG}

ARG BUILD_DATE=unspecified
ARG IMAGE_BUILD_VERSION=unspecified
ARG GIT_COMMIT=unspecified
ARG ISO_VERSION=unspecified
ARG RSTATE=unspecified
ARG SGUSER=259273

RUN echo "$SGUSER:x:$SGUSER:$SGUSER:An Identity for cmutilities:/nonexistent:/bin/false" >>/etc/passwd && \
    echo "$SGUSER:!::0:::::" >>/etc/shadow

# install kubectl
RUN KUBEVERSION="v1.28.4" && \
    curl -LO "https://arm.seli.gic.ericsson.se/artifactory/kubernetes-release-remote-2rc-cache/release/${KUBEVERSION}/bin/linux/amd64/kubectl" && \
    install kubectl /usr/local/bin/kubectl

# Add Apache Confiuration Update Script
COPY --chown=${SGUSER}:${SGUSER} image_content/apache_config_update.sh /var/tmp/apache_config_update.sh

USER $SGUSER
