#!/bin/bash

set -e -x

pushd source-code
  ./mvnw clean package
popd

cp source-code/target/pcfdemo.war  build-output/.
