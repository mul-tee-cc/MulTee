ARG REPO=""
FROM ${REPO}docker.io/library/oraclelinux:8.10

#COPY middlebox.pem /etc/pki/ca-trust/source/anchors/
#RUN update-ca-trust

RUN yum install -y nginx openssl-pkcs11

RUN yum clean all

RUN systemctl enable nginx

RUN ln -sf /host/multee-pkcs11/target/debug/libmultee_pkcs11.so /usr/lib64/pkcs11 && \
    echo module: libmultee_pkcs11.so > /usr/share/p11-kit/modules/multee.module && \
    echo Proof of connection > /usr/share/nginx/html/50x.html

COPY 10-multee.conf /usr/lib/systemd/system/nginx.service.d/10-multee.conf
COPY multee.env /etc/nginx/multee.env
COPY nginx.conf /etc/nginx/nginx.conf


ENTRYPOINT /sbin/init

#ARG GIT_HASH
#LABEL src-ref="${GIT_HASH}"
#ARG GIT_DESC
#LABEL src-desc="${GIT_DESC}"
