# Intent-aware Fuzzing for Android Hardened Application

## Dependencies

Tested on MacOS Sonoma 14.4.1 (23E224) with a 24-core CPU (Apple M2 Ultra) and 192 GB of RAM

- Android SDK (e.g., adb, aapt, emulator)
- python3, BPF module (pip3 install bcc)

## Prerequisites

### 1. ARM64 android device with root privilege
- We test AHAFuzz with an emulator (android-33;google_apis;arm64-v8a-17)
- You can download emulator with sdkmanager

### 2. AOSP build environment
- AHAFuzz is based on Monkey, the built-in Android fuzzer.
- To build AHAFuzz, the recommended approach is to replace the Monkey code with the AHAFuzz code in AOSP.
- Pre-built fuzzer binaries are provided in the `prebuilt/` directory.
- For more details, refer to the README in the Fuzzer_src directory.

### 3. bpftools build environment
- Because current android kernel are not user-friendly to use eBPF, we have to cross-compile bpftools, which is eBPF framework tools.
- Please refer to the following link: https://github.com/facebookexperimental/ExtendedAndroidTools
- After building bpftools, you have to increase the probe limit defined in the BCC code.
- **Pre-built bpftools** is provided in the `prebuilt/bpftools/` directory.

## How to Run AHAFuzz

### 1. Setup environment variables
Edit `env/setup.sh` to configure your environment:
- Set `ANDROID_HOME` to your Android SDK path
- Set `AHAFUZZ_EMULATOR` if using a different device (default: emulator-5554)

```bash
source env/setup.sh
```

### 2. Device Setup
Use pre-built bpftools from `prebuilt/bpftools/` directory, or build from source (see Appendix 1).

```bash
# Start Android emulator
emulator -avd [YOUR_EMULATOR_NAME]  # e.g., AHAFuzz_emulator

# Package bpftools
cd prebuilt
tar -czvf bpftools-arm64.tar.gz bpftools/
cd ..

# Upload and setup bpftools
adb push prebuilt/bpftools-arm64.tar.gz /data/local/tmp
adb root
adb shell
cd /data/local/tmp
mkdir message
tar -xvf bpftools-arm64.tar.gz
cd bpftools
sh setup.sh
```

### 3. Setting AHAFuzz script
```bash
sh script/setting.sh
```

### 4. Install target application
- `manifest_analysis.py` collects information that need to fuzz(e.g., UID of target app, intent information defined in manifest file)
```bash
python3 ebpf_tracer/manifest_analysis.py [APK_PATH]
# Example: python3 ebpf_tracer/manifest_analysis.py /path/to/app.apk
```

### 5. Run eBPF Program
```bash
adb root && adb shell
cd /data/local/tmp/bpftools
./python3 AHAFuzz.py
```

### 6. Run fuzzer
- Because AHAFuzz is based on monkey fuzzer, usage is also same.
- One additional option is "--running-minutes {time}".
```bash
adb -s $AHAFUZZ_EMULATOR shell CLASSPATH=/data/local/tmp/AHAFuzz.jar /system/bin/app_process /data/local/tmp/ com.android.commands.monkey.Monkey -p [TARGET_PACKAGE] --running-minutes [FUZZING_TIME] --ape sata

# Example: 
adb -s $AHAFUZZ_EMULATOR shell CLASSPATH=/data/local/tmp/AHAFuzz.jar /system/bin/app_process /data/local/tmp/ com.android.commands.monkey.Monkey -p com.example.app --running-minutes 30 --ape sata
```

### 7. Get result
```bash
sh script/GetResult.sh

# Or specify a custom result directory:
sh script/GetResult.sh -d custom_result
```

## Code Structure

AHAFuzz is implemented with Python 3.6+, BCC (BPF Compiler Collection), and Android SDK tools.

```
AHAFuzz/
├── ebpf_tracer/                    # eBPF implementation component
│   ├── AHAFuzz.py                 # Main eBPF controller
│   ├── manifest_analysis.py       # AndroidManifest.xml analysis
│   ├── processing.py              # ART runtime helper functions
│   ├── bpf_prog/                  # eBPF kernel programs
│   │   └── AHAFuzzTracer_bpf.c   # eBPF C program
├── Fuzzer_src/                    # Fuzzer source code
│   └── monkey/                    # Modified Android Monkey fuzzer
├── prebuilt/                      # Pre-built binaries
│   ├── AHAFuzz.jar               # Pre-built fuzzer (default mode)
│   ├── ape.jar                    # GUI Fuzzer
│   └── bpftools/                  # Pre-built bpftools for ARM64
├── obj_recover/                   # Java object field offset recovery tool
│   ├── OffsetAnalysis.py         # Main analysis tool
│   └── input/                    # Input files for analysis
├── script/                        # Utility scripts
│   ├── setting.sh                 # Environment setup
│   ├── clean.sh                   # Cleanup script
│   ├── GetResult.sh               # Result collection
│   ├── AnalysisResult.py          # Result analysis
├── env/                           # Environment configuration
│   └── setup.sh                   # Environment variables setup
```

## Appendix

### 1. How to increase the probe limit defined in the BCC code
```bash
tar -xvf bpftools-arm64.tar.gz
cd bpftools/lib/python3.10/site-packages
unzip bcc-0.27.0-py3.10.egg
sed -i '' -E 's/(_default_probe_limit = )[0-9]+/\150000/' bcc/__init__.py // change probe limit to 50000
zip -r bcc-0.27.0-py3.10.egg bcc
cd ../../../..
tar -czvf bpftools-arm64.tar.gz bpftools 
```

### 2. How to turn off JIT
```bash
adb root && adb shell
setprop dalvik.vm.usejit false 
setprop dalvik.vm.usejitprofiles false
# getprop | grep jit   // output                                                  
[dalvik.vm.usejit]: [false]
[dalvik.vm.usejitprofiles]: [false]
```
