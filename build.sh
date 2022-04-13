#!/bin/bash
if [ ! -d "build" ]
then
    mkdir build
    pushd build
    cmake .. -DCMAKE_BUILD_TYPE=Debug -GNinja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DWITH_PROCPS=OFF -DMULTICORE=ON
    popd
fi
pushd build >/dev/null
ninja
popd >/dev/null
