// May require
// GOPROXY=https://artifactory.multee.cc:443/artifactory/snapshots/com/cc/multee/multee-golang/,https://artifactory.multee.cc:443/artifactory/go-release/

module go-sample

go 1.13

replace multee.cc/multee v0.7.0 => ../../multee-golang

require multee.cc/multee v0.7.0
