ARG BASE_IMAGE
FROM ${BASE_IMAGE}

LABEL name="odh-notebook-jupyter-datascience-ubi8-python-3.8" \
    summary="Jupyter data science notebook image for ODH notebooks" \
    description="Jupyter data science notebook image with base Python 3.8 builder image based on UBI8 for ODH notebooks" \
    io.k8s.display-name="Jupyter data science notebook image for ODH notebooks" \
    io.k8s.description="Jupyter data science notebook image with base Python 3.8 builder image based on UBI8 for ODH notebooks" \
    authoritative-source-url="https://github.com/opendatahub-io/notebooks" \
    io.openshift.build.commit.ref="main" \
    io.openshift.build.source-location="https://github.com/opendatahub-io/notebooks/tree/main/jupyter/datascience/ubi8-python-3.8" \
    io.openshift.build.image="quay.io/opendatahub/workbench-images:jupyter-datascience-ubi8-python-3.8"

WORKDIR /opt/app-root/bin

# Install Python packages and Jupyterlab extensions from Pipfile.lock
COPY Pipfile.lock ./
# Copy Elyra setup to utils so that it's sourced at startup
COPY setup-elyra.sh ./utils/

RUN echo "Installing softwares and packages" && \
    micropipenv install && \
    rm -f ./Pipfile.lock

COPY utils ./utils/

# OS Packages needs to be installed as root
USER root

# Install usefull OS packages
RUN dnf install -y jq unixODBC git-lfs libsndfile

# Disable announcement plugin of jupyterlab
RUN jupyter labextension disable "@jupyterlab/apputils-extension:announcements"

# Install MongoDB Client, We need a special repo for MongoDB as they do their own distribution
COPY mongodb-org-6.0.repo-x86_64 /etc/yum.repos.d/mongodb-org-6.0.repo

RUN dnf install -y mongocli

# Install MSSQL Client, We need a special repo for MSSQL as they do their own distribution
COPY mssql-2022.repo-x86_64 /etc/yum.repos.d/mssql-2022.repo

RUN ACCEPT_EULA=Y dnf install -y mssql-tools18 unixODBC-devel

ENV PATH="$PATH:/opt/mssql-tools18/bin"

# Other apps and tools installed as default user
USER 1001

# setup path for runtime configuration
RUN mkdir /opt/app-root/runtimes && \
    # switch to Data Science Pipeline \
    cp utils/pipeline-flow.svg /opt/app-root/lib/python3.8/site-packages/elyra/static/icons/kubeflow.svg && \
    sed -i "s/Kubeflow Pipelines/Data Science/g" /opt/app-root/lib/python3.8/site-packages/elyra/pipeline/runtime_type.py && \
    sed -i "s/Kubeflow Pipelines/Data Science Pipelines/g" /opt/app-root/lib/python3.8/site-packages/elyra/metadata/schemas/kfp.json && \
    sed -i "s/kubeflow-service/data-science-pipeline-service/g" /opt/app-root/lib/python3.8/site-packages/elyra/metadata/schemas/kfp.json && \
    sed -i "s/\"default\": \"Argo\",/\"default\": \"Tekton\",/g" /opt/app-root/lib/python3.8/site-packages/elyra/metadata/schemas/kfp.json && \
    # Workaround for passing ssl_sa_cert
    patch /opt/app-root/lib/python3.8/site-packages/elyra/pipeline/kfp/kfp_authentication.py -i utils/kfp_authentication.patch && \
    patch /opt/app-root/lib/python3.8/site-packages/elyra/pipeline/kfp/processor_kfp.py -i utils/processor_kfp.patch && \
    # Workaround for elyra pipeline validation command
    patch /opt/app-root/lib/python3.8/site-packages/elyra/cli/pipeline_app.py -i utils/pipeline_app.patch && \
    patch /opt/app-root/lib/python3.8/site-packages/elyra/pipeline/pipeline_definition.py -i utils/pipeline_definition.patch && \
    # switch to Data Science Pipeline in component catalog \
    DIR_COMPONENT="/opt/app-root/lib/python3.8/site-packages/elyra/metadata/schemas/local-directory-catalog.json" && \
    FILE_COMPONENT="/opt/app-root/lib/python3.8/site-packages/elyra/metadata/schemas/local-file-catalog.json" && \
    URL_COMPONENT="/opt/app-root/lib/python3.8/site-packages/elyra/metadata/schemas/url-catalog.json" && \
    tmp=$(mktemp) && \
    jq '.properties.metadata.properties.runtime_type = input' $DIR_COMPONENT utils/component_runtime.json > "$tmp" && mv "$tmp" $DIR_COMPONENT && \
    jq '.properties.metadata.properties.runtime_type = input' $FILE_COMPONENT utils/component_runtime.json > "$tmp" && mv "$tmp" $FILE_COMPONENT && \
    jq '.properties.metadata.properties.runtime_type = input' $URL_COMPONENT utils/component_runtime.json > "$tmp" && mv "$tmp" $URL_COMPONENT && \
    sed -i "s/metadata.metadata.runtime_type/\"DATA_SCIENCE_PIPELINES\"/g" /opt/app-root/share/jupyter/labextensions/@elyra/pipeline-editor-extension/static/lib_index_js.*.js && \
    # Remove Elyra logo from JupyterLab because this is not a pure Elyra image \
    sed -i 's/widget\.id === \x27jp-MainLogo\x27/widget\.id === \x27jp-MainLogo\x27 \&\& false/' /opt/app-root/share/jupyter/labextensions/@elyra/theme-extension/static/lib_index_js.*.js && \
    # Replace Notebook's launcher, "(ipykernel)" with Python's version 3.x.y \
    sed -i -e "s/Python.*/$(python --version| cut -d '.' -f-2)\",/" /opt/app-root/share/jupyter/kernels/python3/kernel.json && \
    # Remove default Elyra runtime-images \
    rm /opt/app-root/share/jupyter/metadata/runtime-images/*.json && \
    # Fix permissions to support pip in Openshift environments \
    chmod -R g+w /opt/app-root/lib/python3.8/site-packages && \
    fix-permissions /opt/app-root -P

# Copy Elyra runtime-images definitions and set the version
COPY runtime-images/ /opt/app-root/share/jupyter/metadata/runtime-images/

WORKDIR /opt/app-root/src
