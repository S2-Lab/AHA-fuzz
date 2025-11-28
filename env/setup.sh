#!/bin/bash

# AHAFuzz Environment Setup Script

# =============================================================================
# Android SDK Configuration
# =============================================================================
# *** REQUIRED: Set your Android SDK path ***
export ANDROID_HOME="/path/to/android-sdk"

export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$PATH:$ANDROID_HOME/platform-tools"
export PATH="$PATH:$ANDROID_HOME/emulator"
export PATH="$PATH:$ANDROID_HOME/tools"

# *** REQUIRED: Set your build-tools version (e.g., 33.0.0, 34.0.0) ***
export PATH="$PATH:$ANDROID_HOME/build-tools/33.0.0"

# =============================================================================
# AHAFuzz Configuration
# =============================================================================
export AHAFUZZ_HOME="$(pwd)"
export AHAFUZZ_EBPF_PATH="$AHAFUZZ_HOME/ebpf_tracer"
export AHAFUZZ_SCRIPT_PATH="$AHAFUZZ_HOME/script"

# *** REQUIRED: Set your emulator/device serial number ***
export AHAFUZZ_EMULATOR="emulator-5554"

# =============================================================================
# eBPF Configuration
# =============================================================================
export AHAFUZZ_MAX_STR_LEN="112"
export AHAFUZZ_MAX_STR_COUNT="4"
export AHAFUZZ_TARGET_LATENCY="1000000"

# =============================================================================
# Python Configuration
# =============================================================================
export PYTHONPATH="$AHAFUZZ_HOME:$PYTHONPATH"

echo "AHAFuzz environment variables set successfully!"
