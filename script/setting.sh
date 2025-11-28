#!/bin/bash

EMULATOR_ID="${AHAFUZZ_EMULATOR:-emulator-5554}"

adb -s "$EMULATOR_ID" push ${AHAFUZZ_EBPF_PATH:-ebpf_tracer}/* /data/local/tmp/bpftools
adb -s "$EMULATOR_ID" push prebuilt/*.jar /data/local/tmp/
adb -s "$EMULATOR_ID" push ${AHAFUZZ_SCRIPT_PATH:-script}/clean.sh /data/local/tmp/