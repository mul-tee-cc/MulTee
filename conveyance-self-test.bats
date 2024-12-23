setup() {
  [ -f "${BATS_PARENT_TMPNAME}.skip" ] && skip "skip remaining tests"
  load 'deps/bats-support/load'
  load 'deps/bats-assert/load'
  load 'deps/bats-file/load'
}

teardown() {
  [  "${BATS_TEST_COMPLETED}" = 1 ] || touch "${BATS_PARENT_TMPNAME}.skip"
}

teardown_file() {
  rm -f touch "${BATS_PARENT_TMPNAME}.skip"
  make .stop-test-containers SYSROOT_TOUCH=
}

# bats test_tags=lang_wrappers
@test "MulTee GoLang works" {
  run make run-build-container SYSROOT_TOUCH= WHAT='make test-golang'
  assert_output --partial 'Tested Ok: true'
  assert_file_exists sample/golang/go-sample
}

# bats test_tags=lang_wrappers
@test "MulTee Java works" {
  run make run-build-container SYSROOT_TOUCH= WHAT='make test-java'
  assert_output --partial 'Tested Ok: true'
}

# bats test_tags=pkcs11_wrapper
@test "MulTee PKCS11 provides TLS termination in Nginx" {
  run make test-pkcs11
  assert_output --partial 'Proof of connection'
}

# bats test_tags=tofu_attestation
@test "MulTee TOFU attestation works" {
  run make .stop-test-containers SYSROOT_TOUCH=
  run make .start-pykmip SYSROOT_TOUCH=
  run make run-build-container SYSROOT_TOUCH= WHAT='make test-tofu-2'
  assert_output --partial 'Tested Ok: true'
}

# bats test_tags=dcap_attestation
@test "MulTee DCAP attestation works" {
  run make .stop-test-containers SYSROOT_TOUCH=
  run make run-build-container SYSROOT_TOUCH= WHAT='make .build-triplea-service publish-golang .build-go-sample'
  run make .start-pykmip .start-triplea SYSROOT_TOUCH=
  run make run-build-container SYSROOT_TOUCH= WHAT='make test-triplea-dcap'
  assert_output --partial 'Tested Ok: true'
}

# bats test_tags=sevsnp_attestation
@test "MulTee SEV-SNP attestation works" {
  run make .stop-test-containers SYSROOT_TOUCH=
  run make run-build-container SYSROOT_TOUCH= WHAT='make .build-triplea-service publish-golang .build-go-sample'
  run make .start-pykmip .start-triplea SYSROOT_TOUCH=
  run make run-build-container SYSROOT_TOUCH= WHAT='make test-triplea-sevsnp'
  assert_output --partial 'Tested Ok: true'
}

# bats test_tags=multee_server
@test "MulTee Server works" {
  run make .stop-test-containers SYSROOT_TOUCH=
  run make run-build-container SYSROOT_TOUCH= WHAT='make multee-server publish-golang .build-go-sample'
  run make .start-multee-server SYSROOT_TOUCH=
  run make run-build-container SYSROOT_TOUCH= WHAT='make test-multee-server'
  assert_output --partial 'Tested Ok: true'
}
