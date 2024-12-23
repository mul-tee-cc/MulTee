ARG REPO=""
FROM ${REPO}docker.io/library/oraclelinux:8.10

#COPY middlebox.pem /etc/pki/ca-trust/source/anchors/
#RUN update-ca-trust

RUN yum -y groupinstall "Development Tools"
RUN yum -y install epel-release
RUN yum -y install --setopt=tsflags=nodocs capnproto wget which patchelf
RUN yum -y install --setopt=tsflags=nodocs llvm-toolset-13.0.1
RUN yum -y install --setopt=tsflags=nodocs go-toolset
RUN yum -y install --setopt=tsflags=nodocs java-1.8.0-openjdk-devel maven zip unzip rcs file
RUN yum -y install --setopt=tsflags=nodocs make bash-completion

RUN curl -L -o /etc/yum.repos.d/sbt-rpm.repo https://www.scala-sbt.org/sbt-rpm.repo
RUN yum -y install sbt

RUN yum clean all

ENV CARGO_HOME=/tmp/.cargo \
    RUSTUP_HOME=/tmp/rustup \
    PATH="$PATH:/tmp/.cargo/bin"

RUN curl -L -o /tmp/rustup-init \
        https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init && \
    chmod u+x /tmp/rustup-init && \
    /tmp/rustup-init -y --default-toolchain 1.74.0 && \
    rustup toolchain add nightly-2023-11-17-x86_64-unknown-linux-gnu && \
    rustup component add rust-src --toolchain nightly-2023-11-17-x86_64-unknown-linux-gnu

RUN curl -L -o sgx_linux_x64_sdk.bin \
        https://download.01.org/intel-sgx/sgx-linux/2.17.1/distro/rhel8.4-server/sgx_linux_x64_sdk_2.17.101.1.bin && \
    chmod u+x sgx_linux_x64_sdk.bin && \
    mkdir /opt/intel && cd /opt/intel && echo 'yes' | ../../sgx_linux_x64_sdk.bin && \
    rm -f ../../sgx_linux_x64_sdk.bin  /tmp/rustup-init  && \
    source /opt/intel/sgxsdk/environment

ENV SGX_SDK=/opt/intel/sgxsdk \
    LD_LIBRARY_PATH=/opt/intel/sgxsdk/sdk_libs

RUN curl -L https://download.01.org/intel-sgx/sgx-dcap/1.14/linux/distro/rhel8.4-server/sgx_rpm_local_repo.tgz | \
    tar xzf - sgx_rpm_local_repo/libsgx-{dcap-ql,dcap-ql-devel,pce-logic,qe3-logic}-1.14.100.3-1.el8.x86_64.rpm && \
    rpm -i --nodeps sgx_rpm_local_repo/libsgx-{dcap-ql,dcap-ql-devel,pce-logic,qe3-logic}-1.14.100.3-1.el8.x86_64.rpm && \
    rm -rf sgx_rpm_local_repo


