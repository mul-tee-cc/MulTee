#

NIGHTLY = nightly-2023-11-17-x86_64-unknown-linux-gnu
#NIGHTLY = nightly-2024-02-22-x86_64-unknown-linux-gnu

RELEASE ?= debug

ifneq ($(RELEASE),debug)
RELEASE_OPT = --release
endif

ifneq ($(MODE),hw)
MODE = sim
SGX_MODE = SIM
else
MODE = hw
endif

SYSROOT_NAME = sysroot-$(MODE)-$(RELEASE)
SYSROOT_LOC_BASE = trusted-sgx/$(SYSROOT_NAME)/lib/rustlib/x86_64-unknown-linux-sgx
SYSROOT_LOC = $(SYSROOT_LOC_BASE)/lib
SYSROOT_TARGET_DIR = target/sysroot-$(MODE)
SYSROOT_REAL_DIR = trusted-sgx/$(SYSROOT_TARGET_DIR)/x86_64-unknown-linux-sgx/$(RELEASE)/deps

TRUSTED_LOC = trusted-sgx/target/x86_64-unknown-linux-sgx/$(RELEASE)/libtrusted_sgx.a
UNTRUSTED_LOC = untrusted-sgx/target/$(RELEASE)/libuntrusted_sgx.so
JNI_LOC = multee-jni/target/$(RELEASE)/libmultee_jni.so
CGO_LOC = multee-cgo/target/$(RELEASE)/libmultee_cgo.a
PKCS11_LOC = multee-pkcs11/target/$(RELEASE)/libmultee_pkcs11.so

# TODO: version consistency
GO_VER := $(shell sed '/require multee.cc.multee/ { s/.* v\([0-9.]\+\)$$/\1/; p; }; d' sample/golang/go.mod)
JAVA_VER := $(shell sed '/version\s*:=/ { s/.*"\([0-9.]\+\)".*/\1/; p;}; d' multee-java/build.sbt)
VER := $(GO_VER)

PODMAN ?= podman

CBC := $(CURDIR)/container-build-cache
MOUNT_BUILD_CACHE = $(shell test -d $(CBC); mkdir -p $(CBC)/cargo/registry $(CBC)/ivy2 $(CBC)/git $(CBC)/go-pkg $(CBC)/coursier $(CBC)/.m2 2> /dev/null; echo "-v $(CBC)/cargo/registry:/tmp/.cargo/registry -v $(CBC)/git:/tmp/.cargo/git -v $(CBC)/ivy2:/root/.ivy2 -v $(CBC)/coursier:/root/.cache/coursier -v $(CBC)/.m2:/root/.m2 -v $(CBC)/go-pkg:/tmp/go -v $(CURDIR)/artifactory:/w/artifactory --env GOPATH=/tmp/go --env GOCACHE=/tmp/cache")

assert_inside_container = @test -n "${container}" || { echo Target "<$@>" cannot be invoked outside of a container; false; }
assert_outside_container = @test -z "${container}" || { echo Target "<$@>" cannot be invoked inside a container; false; }

run_build_container = $(PODMAN) run --rm -ti --user 0:0 $(MOUNT_BUILD_CACHE) -v $(CURDIR):/w -w /w multee-build ${1}

ifeq (${container},)
run-build-container:
	@$(call run_build_container,$(WHAT))
endif

PYKMIP_HOST = $(if ${container},host.docker.internal,localhost)
TRIPLEA_HOST = $(PYKMIP_HOST)
MULTEE_SERVER_HOST = $(PYKMIP_HOST)

run-java-sample = java -jar sample/java/target/java-sample-$(JAVA_VER).jar $(1) $(2) $(3)

define and-again
again-$1: .$1-clean .$1
.$1-clean:
	@rm -f .$1
endef

# new line
define n


endef


.DEFAULT_GOAL := .help
.help:
	@$(info ====== Provide explicit goal =============================================)
	@$(info ====== Use bash autocompletion to list supported goals ===================)
	@$(error Usage)

.extract-plantuml:
	@sed '/www.plantuml.com/,/<.details/ { /www.plantuml.com/ { s#^.\[\([a-z-]\+\)\].http:..www.plantuml.com.*#cat > docs/\1.puml <<EOF#; p; }; /@startuml/,/@enduml/ {p;}; /@enduml/ { s/.*/EOF/; p; }  }; d' README.md|sh

####################################### Tests

test-data/literals.zip: 
	@( cd test-data && ./gen-literals.sh )
test-data/identity.zip:
	@( cd test-data && ./make-triple-a-identity.sh )

test-triplea-dcap: .check-pykmip .check-triplea test-data/identity.zip
	@RUST_LOG=info                    ./sample/golang/go-sample test kmip://$(PYKMIP_HOST):5696/TestKey?triple_a=https://$(TRIPLEA_HOST):2443/\&triple_a_csr_cn=acct test-data/identity.zip
test-triplea-sevsnp: .check-pykmip .check-triplea test-data/identity.zip
	@RUST_LOG=info MULTEE_FORCE_SNP=y ./sample/golang/go-sample test kmip://$(PYKMIP_HOST):5696/TestKey?triple_a=https://$(TRIPLEA_HOST):2443/\&triple_a_csr_cn=acct test-data/identity.zip

test-multee-server: .check-multee-server test-data/identity.zip
	@RUST_LOG=info ./sample/golang/go-sample test remote://$(MULTEE_SERVER_HOST):4443/TestKey test-data/identity.zip

ifeq (${container},)

.stop-test-containers:
	@$(PODMAN) rm -f test-multee-tls
	@$(PODMAN) rm -f test-triple-a
	@$(PODMAN) rm -f test-multee-pykmip
	@$(PODMAN) rm -f test-multee-server

conveyance-self-test:
	@deps/bats-core/bin/bats --report-formatter junit conveyance-self-test.bats

test-pkcs11: test-data/literals.zip
ifeq ($(origin SYSROOT_TOUCH), undefined)
	@$(warning to avoid rebuild of container version of PKCS11, test-pkcs11 can be invoked with SYSROOT_TOUCH=, as follows:$(n)> make test-pkcs11 SYSROOT_TOUCH= )
	@sleep 3
endif
	@$(call run_build_container,make multee-pkcs11)
	@$(PODMAN) rm -f test-multee-tls

	@echo -n Starting ...
	@$(PODMAN) run --rm -d --name test-multee-tls -v /sys/fs/cgroup:/sys/fs/cgroup:ro -p 1443:1443 -v $(CURDIR):/host test-pkcs11
	@echo ========================================================================
	@echo ==== Testing with literal keys from literals.zip =================
	@echo ========================================================================
	@echo Running curl -k https://127.127.1.1:1443/50x.html
	@sleep 1
	@curl -k https://127.127.1.1:1443/50x.html
	@echo -n Killing ...
	@$(PODMAN) rm -f test-multee-tls

.start-pykmip:
	@$(PODMAN) container exists test-multee-pykmip || { \
		$(PODMAN) run --rm -d --name test-multee-pykmip -p 5696:5696 -v $(CURDIR):/w test-pykmip && \
		sleep 1 && \
		$(PODMAN) exec test-multee-pykmip /perform.sh create_aes_key create_rsa_key create_hmac_key; \
	}
	@$(PODMAN) cp test-multee-pykmip:/etc/pykmip/state/ -|tar -x -f - -C test-data --strip-components=1 state/selfsigned.{crt,key}
	@echo PyKMIP container will be stopped after 1800 seconds

.start-triplea:
	@test-data/provision-triple-a-secrets.sh
	@$(PODMAN) run --rm -d --name test-triple-a -p 2443:2443 -v $(CURDIR):/w -w /w multee-build timeout 1800 java -jar triple-a-service/target/triple-a-service.jar test-data/triplea.p12 test-data/id-trust-ca.crt test-data/grant-signing.crt test-data/grant-signing.key
	@echo TripleA Service container will be stopped after 1800 seconds

.start-multee-server: test-data/literals.zip
	@( cd test-data && ./make-multee-server-cert.sh )
	$(PODMAN) run --rm -d --name test-multee-server -p 4443:4443 -v $(CURDIR):/w -w /w multee-build timeout --foreground 1800 ./multee-server/target/$(RELEASE)/multee-server "[::]:4443" --auth-cert test-data/selfsigned.crt --cert test-data/multee-server.pem --key test-data/multee-server.pkey --keynames TestKey,HmacKey,RsaKey,EccKey --literals test-data/literals.zip
	@echo MulTee Server container will be stopped after 1800 seconds

endif

.check-pykmip:
	@sleep 1
	@openssl s_client -connect $(PYKMIP_HOST):5696 |& grep -q ^SSL-Session ||  { echo PyKMIP container isnt running; false; }

.check-triplea:
	@sleep 1
	@sleep 0.2| openssl s_client -connect $(TRIPLEA_HOST):2443 |& grep -q ^SSL-Session ||  { echo Triple-A Service container isnt running; false; }

.check-multee-server:
	@sleep 1
	@sleep 0.2| openssl s_client -connect $(MULTEE_SERVER_HOST):4443 |& grep -q ^CN ||  { echo MulTee Server container isnt running; false; }

.build-triplea-service:
	@which sbt > /dev/null 2> /dev/null || { echo -e SBT not found. Try instead: \\n$(MAKE)  --eval \'WHAT = make <TARGET>\' run-build-container \\n ; false; }
	@echo "Publishing TripleA"
	@( cd triple-a-service; sbt myPackage; )


test-tofu-2: publish-java .build-java-sample .check-pykmip .tofu-attestation
	@echo ========================================================================
	@echo ==== Testing with key fetched from KMIP providing TOFU attestation =====
	@echo ========================================================================
	@$(call run-java-sample,test-with-key,kmip://$(PYKMIP_HOST):5696/TestKey,test-data/tofu.zip)
.tofu-attestation:
	@java -jar multee-java/target/multee-java-$(JAVA_VER).jar tofu test-data/tofu.zip CN=acct
	@test-data/make-tofu-grant.sh test-data/tofu.zip


test-java: publish-java .build-java-sample test-data/literals.zip
	@echo ========================================================================
	@echo ==== Testing with literal keys from literals.zip =================
	@echo ========================================================================
	$(call run-java-sample,test-with-key,file://./EccKey,test-data/literals.zip)
.build-java-sample:
	@which mvn 2> /dev/null > /dev/null || { echo -e Maven not found. Consider instead: \\n$(MAKE)  --eval \'WHAT = make <TARGET>\' run-build-container \\n ; false; }
	@echo "Building sample/java"
	@mvn org.apache.maven.plugins:maven-dependency-plugin:3.5.0:purge-local-repository -DmanualInclude=cc.multee:multee-java -Dverbose=true
	@( cd sample/java; mvn package; )

test-golang: publish-golang .build-go-sample test-data/literals.zip
	@echo ========================================================================
	@echo ==== Testing with literal keys from literals.zip =================
	@echo ========================================================================
	sample/golang/go-sample test file://./EccKey test-data/literals.zip
.build-go-sample:
	@echo "Building sample/go"
	@( cd sample/golang; go build; )


####################################### Publish/package

multee-server:	.multee-server
.multee-server:	.multee-untrusted \
				$(UNTRUSTED_LOC) \
				multee-server/Cargo.toml \
				$(wildcard multee-server/src/**/*.rs)
	@echo Building MulTee Server
	@(cd multee-server; cargo build $(RELEASE_OPT); )
	@touch .multee-server

publish-java: .publish-java
.publish-java:  .multee-jni \
				multee-java/build.sbt \
				$(wildcard multee-java/src/main/java/**/*.java) \
				$(wildcard multee-java/src/main/resources/*)
	@which sbt > /dev/null 2> /dev/null || { echo -e SBT not found. Try instead: \\n$(MAKE)  --eval \'WHAT = make <TARGET>\' run-build-container \\n ; false; }
	@echo "Publishing multee-java v$(JAVA_VER)"
	@ln -snf ../../../../$(JNI_LOC) multee-java/src/main/resources/
	@( cd multee-java; sbt publish; )
	@touch .publish-java


publish-golang: .publish-golang
#$(eval $(call and-again,publish-golang))
.publish-golang: .multee-cgo \
             multee-golang/go.mod \
		     $(wildcard multee-golang/*.go) \
		     $(wildcard multee-golang/*.c) \
		     $(wildcard multee-golang/*.h)
	@which go > /dev/null 2> /dev/null || { echo -e GoLang not found. Consider instead: \\n$(MAKE)  --eval \'WHAT = make <TARGET>\' run-build-container \\n ; false; }
	@echo Publishing multee-golang v$(GO_VER)
	@ln -snf ../$(CGO_LOC) multee-golang/
	@mkdir -p multee.cc artifactory/go/multee.cc/multee/@v 2> /dev/null
	@ln -snf ../multee-golang multee.cc/multee@v$(GO_VER)
	@echo "{\"Version\":\"v$(GO_VER)\",\"Time\":\"$(date --iso-8601=seconds)\"}" > artifactory/go/multee.cc/multee/@v/v$(GO_VER).info
	@zip -1 artifactory/go/multee.cc/multee/@v/v$(GO_VER).zip multee.cc/multee@v$(GO_VER)/{*.go,go.mod,*.h,*.a}
	@touch .publish-golang


multee-pkcs11:  .multee-pkcs11
.multee-pkcs11: .multee-untrusted \
				$(UNTRUSTED_LOC) \
				multee-pkcs11/Cargo.toml \
				$(wildcard multee-pkcs11/src/**/*.rs)
	@echo Building pkcs11
	@(cd multee-pkcs11; cargo build $(RELEASE_OPT); )
	@touch .multee-pkcs11

####################################### Bindings

.multee-jni: .multee-untrusted \
			  $(UNTRUSTED_LOC) \
			  multee-jni/Cargo.toml \
			  multee-jni/build.rs \
			  $(wildcard multee-jni/src/*.rs)
	@echo Building jni
	@( cd multee-jni; cargo build $(RELEASE_OPT); )
	@touch .multee-jni

.multee-cgo:    .multee-untrusted \
				$(UNTRUSTED_LOC) \
				multee-cgo/build.rs \
				multee-cgo/Cargo.toml \
				$(wildcard multee-java/src/*.rs)
	@echo Building cgo
	@( cd multee-cgo; cargo build $(RELEASE_OPT); )
	@touch .multee-cgo

####################################### Untrusted

#$(eval $(call and-again,multee-untrusted))
.multee-untrusted: .multee-trusted  \
				   untrusted-sgx/Cargo.toml \
				   untrusted-sgx/build.rs \
				   $(wildcard untrusted-sgx/src/*.rs)
	@echo Building untrusted
	@( cd untrusted-sgx && cargo +$(NIGHTLY) build $(RELEASE_OPT); )
	@rm -f .multee-untrusted; touch .multee-untrusted

####################################### Trusted

#$(eval $(call and-again,multee-trusted))
.multee-trusted: .$(SYSROOT_NAME) \
				 trusted-sgx/Cargo.toml \
				 trusted-sgx/build.rs \
				 $(wildcard trusted-sgx/src/*.rs) \
				 $(wildcard trusted-sgx/resources/*)
	@echo Building trusted with sysroot at $(CURDIR)/trusted-sgx/$(SYSROOT_NAME)
	@( cd trusted-sgx && RUSTFLAGS=--sysroot=$(CURDIR)/trusted-sgx/$(SYSROOT_NAME) cargo +$(NIGHTLY) build --features multee_sgx $(RELEASE_OPT); )
	#( cd trusted-sgx && SGX_MODE=$(SGX_MODE) RUSTFLAGS=--sysroot=$(CURDIR)/trusted-sgx/$(SYSROOT_NAME) cargo +$(NIGHTLY) build --features multee_sgx $(RELEASE_OPT); )
	@touch .multee-trusted

####################################### Sysroot

SYSROOT_PLATFORM = $(if ${container},container-$(MODE)-$(RELEASE),host-$(MODE)-$(RELEASE))
SYSROOT_TOUCH ?= $(shell grep -sq $(SYSROOT_PLATFORM) .sysroot-platform || echo $(SYSROOT_PLATFORM) > .sysroot-platform; echo .sysroot-platform)

.$(SYSROOT_NAME): $(SYSROOT_TOUCH)
	@echo Checking sysroot in: $(SYSROOT_LOC_BASE)/lib
	@-rm -rf trusted-sgx/target
	@test -d $(SYSROOT_LOC) -a "$(shell readlink $(SYSROOT_LOC))" = trusted-sgx/$(SYSROOT_REAL_DIR) || \
	{( cd deps/incubator-teaclave-sgx-sdk/rustlib/std && \
		SGX_MODE=$(SGX_MODE) cargo +$(NIGHTLY) build -Z build-std=core,alloc \
		--target ../x86_64-unknown-linux-sgx.json --target-dir=../../../../trusted-sgx/$(SYSROOT_TARGET_DIR) \
		--features net,thread,untrusted_time,untrusted_fs,backtrace $(RELEASE_OPT); ) && \
		mkdir -p $(SYSROOT_LOC_BASE) && \
		ln -snf ../../../../$(SYSROOT_TARGET_DIR)/x86_64-unknown-linux-sgx/$(RELEASE)/deps $(SYSROOT_LOC) \
	;}
	@sed -i '/^rustflags/ s#--sysroot=\([^"]\+\)"#--sysroot=$(CURDIR)/trusted-sgx/$(SYSROOT_NAME)"#' trusted-sgx/.cargo/config
	@touch .$(SYSROOT_NAME)

####################################### Cleanup

# Use if debug<->release or HW<->SIM or native<->container change
clean-all: .soft-clean
	@-rm -rf .sysroot* */target sample/*/target

.soft-clean:
	@rm -f .multee* .publish*

####################################### Images

ifeq (${container},)

container-images:
	@$(PODMAN) build --rm -t multee-build images/multee-build
	@$(PODMAN) build --rm -t test-pkcs11  images/pkcs11
	@$(PODMAN) build --rm -t test-pykmip  images/pykmip

endif
