#!/bin/bash
################################################################################
# GetResult.sh - AHAFuzz Result Collection Script
# 
# Description:
#   Collects fuzzing results from Android emulator/device and runs analysis.
#   Automatically handles result directory versioning (result, result1, result2, ...)
#
# Usage:
#   ./GetResult.sh [OPTIONS]
#
# Options:
#   -d DIR       Specify base result directory (default: result)
#   -h           Show this help message
#
# Environment Variables:
#   AHAFUZZ_EMULATOR       Emulator/device serial (default: emulator-5554)
#   AHAFUZZ_SCRIPT_PATH    Path to AHAFuzz script directory (default: script)
################################################################################

# Default configuration - use environment variable or default value
EMULATOR_SERIAL="${AHAFUZZ_EMULATOR:-emulator-5554}"
BASE_DIR="result"

# Parse command line arguments
while getopts "d:h" opt; do
    case $opt in
        d)
            BASE_DIR="$OPTARG"
            ;;
        h)
            grep '^#' "$0" | grep -v '#!/bin/bash' | sed 's/^# \?//'
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            echo "Use -h for help" >&2
            exit 1
            ;;
    esac
done

# Find next available result directory
targetDIR="$BASE_DIR"
count=0

# Start infinite loop
while true; do
    # Check if directory exists
    if [ ! -d "$targetDIR" ]; then
        mkdir "$targetDIR"
        
        # Create subdirectory for pickle files
        mkdir "$targetDIR/pkl_files"

        # Collect Hook Info files (AOT compiled method information)
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-bouncycastle.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-core-icu4j.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-core-libart.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-ext.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-framework-graphics.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-framework.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-ims-common.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-okhttp.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-telephony-common.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-voip-common.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_HookInfoboot-apache-xml.oat.pkl "$targetDIR/pkl_files"

        # Collect other essential files
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/mapping.txt "$targetDIR"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_zygote_map.txt "$targetDIR"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/message/bpf_output.json  "$targetDIR"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/DuplicatedData.txt  "$targetDIR"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/result_addr.txt "$targetDIR"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/intentLog.txt "$targetDIR"

        # Collect Interpreter code related files (method index information)
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-bouncycastle.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-core-icu4j.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-core-libart.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-ext.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-framework-graphics.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-framework.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-ims-common.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-okhttp.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-telephony-common.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-voip-common.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_MethodIdxInfo_boot-apache-xml.oat.pkl "$targetDIR/pkl_files"
        adb -s "$EMULATOR_SERIAL" pull /data/local/tmp/tmp_AddrFrameworkMapping.txt "$targetDIR"

        # Run result analysis
        python3 ${AHAFUZZ_SCRIPT_PATH:-script}/AnalysisResult.py "$targetDIR" > "$targetDIR"/AnalysisReport.txt
        break
    else
        # If directory exists, rename (result -> result1 -> result2 -> ...)
        ((count++))
        targetDIR="${BASE_DIR}${count}"
    fi
done
