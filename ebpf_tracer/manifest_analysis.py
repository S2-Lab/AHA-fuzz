"""
AHAFuzz Manifest Analysis Module

This script is used to analyze an APK's AndroidManifest.xml to extract statically
registered intent-filter information (actions, components, exported status) for
receivers, services, and activities. It also retrieves the package name and UID
of the installed application.

Functions:
    install_apk(apk_path): Install an APK on the emulator
    parse_manifest_components(): Parse AndroidManifest.xml and extract intent-filter details
    get_apk_info(apk_path): Get package name and target SDK version
    get_package_uid(package_name): Get the UID of the installed package
    Evaluation1(): Uninstall app, recompile with specific flags, perform oatdump
"""


import subprocess
import re
import os
import json
import time
import sys
import shutil
import hashlib


apk_path = ""
emulator = ""
package_name = ""




def get_indent_level(line):
    """Return the indent level of a line, based on leading spaces (assuming 4 spaces for a tab)"""
    return len(line) - len(line.lstrip(' '))

def parse_manifest_components():
    # using aapt
    output = subprocess.check_output(
        ["aapt", "dump", "xmltree", apk_path, "AndroidManifest.xml"]).decode('utf-8')

    lines = output.split('\n')
    target_indent = None
    target = None
    component_name = None
    intent_filter_indent = None
    implicit_exist = False
    exported = False
    permissions = False
    action_indent = None

    result = []
    for line in lines:
        line_stripped = line.strip()

        # Check if we are in a receiver block

        current_indent = get_indent_level(line)
        if action_indent is not None and current_indent <= action_indent:
            action_indent = None
        if intent_filter_indent is not None and current_indent <= intent_filter_indent:
            intent_filter_indent = None
        if target_indent is not None and current_indent <= target_indent:
            if not implicit_exist:
                result.append(["Explicit_Intent",target,component_name,exported,permissions])
            implicit_exist = False
            target_indent = None
            exported = False
            target = None
            component_name = None
            permissions = False

        if "E: receiver" in line_stripped or "E: service" in line_stripped or "E: activity" in line_stripped :
            if "E: receiver" in line_stripped:
                target = "receiver"
            elif "E: service" in line_stripped:
                target = "service"
            else:
                target = "activity"
            target_indent = get_indent_level(line)
            continue

        # If we're in a receiver block, check for component name
        elif target_indent is not None and intent_filter_indent is None and get_indent_level(line) > target_indent and ("A: android:name" in line_stripped or "(0x01010003)"in line_stripped):
            pattern = r'Raw: "(.*?)"\)'
            match = re.search(pattern, line)
            if match:
                component_name = match.group(1)  # Return string corresponding to first capture group
            else:
                print("error-0")
            continue

        # If we're in a receiver block, check for component name
        elif target_indent is not None and get_indent_level(line) > target_indent and "A: android:permission" in line_stripped:
            permissions = True
            continue

        # If we're in a receiver block, check for component name
        elif target_indent is not None and get_indent_level(line) > target_indent and "A: android:exported" in line_stripped:
            verify_exported = line.split(')')[-1]
            if verify_exported == "0x0":
                exported = False
            else:
                exported = True
            continue

        # If we're in a receiver block, check for intent-filter
        elif target_indent is not None and get_indent_level(line) > target_indent and "E: intent-filter" in line_stripped:
            intent_filter_indent = get_indent_level(line)
            continue

        # If we're in a intent-filter, check for action
        elif intent_filter_indent is not None and get_indent_level(line) > intent_filter_indent and "E: action" in line_stripped:
            action_indent = get_indent_level(line)
            continue

        # If we're in an intent-filter block, extract the Raw value
        elif action_indent is not None and get_indent_level(line) > action_indent and "A: android:name" in line_stripped:
            raw_match = re.search(r'Raw: \"([^\"]+)\"', line)
            if raw_match:
                implicit_exist = True
                result.append([raw_match.group(1),target,component_name,exported,permissions])
            else:
                print("error-1")
            continue

    if os.path.exists(f"bpf_output_{emulator}.json"):
        os.remove(f"bpf_output_{emulator}.json")
    with open(f"bpf_output_{emulator}.json", "a") as f:
        prevent_dup = set()
        for i in result:
            if i[0] != "Explicit_Intent" and i[0] in prevent_dup:
                continue
            prevent_dup.add(i[0])
            event_data = {"action": i[0], 
                          "init": "manifest",
                          "discover_new": 0, 
                          "symbol_table": {},
                          "hint_table": {}, 
                          "count": 0, 
                          "component" : i[1],
                          "name" : i[2],
                          "exported" : i[3],
                          }
            f.write(json.dumps(event_data))
            f.write("\n")
    res = subprocess.run(f"adb -s {emulator} shell sh /data/local/tmp/clean.sh",
                         shell=True, capture_output=True, text=True)
    res = subprocess.run(f"adb -s {emulator} push bpf_output_{emulator}.json /data/local/tmp/message",
                         shell=True, capture_output=True, text=True)
    res = subprocess.run(f"adb -s {emulator} shell mv /data/local/tmp/message/bpf_output_{emulator}.json /data/local/tmp/message/bpf_output.json",
                         shell=True, capture_output=True, text=True)
    return result


def get_apk_info():
    global package_name
    cmd = ["aapt", "dump", "badging", apk_path]
    result = subprocess.check_output(cmd).decode("utf-8")

    # Parsing package name, compileSdkVersion
    package_match = re.search(r"package: name='(.*?)'", result)
    compile_sdk_version_match = re.search(r"targetSdkVersion='(.*?)'", result)

    package_name = package_match.group(1) if package_match else None
    if package_name is not None:
        with open(f"tmp_packageName_{emulator}.txt", "w") as f:
            f.write(package_name)
        res = subprocess.run(f"adb -s {emulator} push tmp_packageName_{emulator}.txt /data/local/tmp/bpftools",
                             shell=True, capture_output=True, text=True)
        res = subprocess.run(f"adb -s {emulator} shell mv /data/local/tmp/bpftools/tmp_packageName_{emulator}.txt /data/local/tmp/bpftools/tmp_packageName.txt",
                             shell=True, capture_output=True, text=True)

    compile_sdk_version = compile_sdk_version_match.group(
        1) if compile_sdk_version_match else None

    return package_name, compile_sdk_version


def get_package_uid(package_name):
    try:
        output = subprocess.check_output(
            ['adb', '-s', emulator, 'shell', 'dumpsys', 'package', package_name]).decode('utf-8')
        match = re.search(r'userId=(\d+)', output)
        if match:
            targetUID = match.group(1)
            with open(f"tmp_targetUID_{emulator}.txt", "w") as f:
                f.write(str(targetUID))
            res = subprocess.run(f"adb -s {emulator} push tmp_targetUID_{emulator}.txt /data/local/tmp/bpftools",
                                 shell=True, capture_output=True, text=True)
            res = subprocess.run(f"adb -s {emulator} shell mv /data/local/tmp/bpftools/tmp_targetUID_{emulator}.txt /data/local/tmp/bpftools/tmp_targetUID.txt",
                                 shell=True, capture_output=True, text=True)
            return targetUID
        else:
            return None
    except Exception as e:
        return str(e)


def install_apk(apk_path):
    try:
        print(['adb', '-s', emulator, 'install', '-g', apk_path])
        output = subprocess.check_output(
            ['adb', '-s', emulator, 'install', '-g', apk_path]).decode('utf-8')
        print(output)
        if 'Success' in output:
            install_without_optimization()
            clean = subprocess.run(f"adb -s {emulator} shell sh /data/local/tmp/clean.sh", shell=True)
            return True, "APK install success"
        else:
            return False, output
    except Exception as e:
        return False, str(e)


def install_without_optimization():
    # Find .odex file using package_name
    print(['adb', '-s', emulator, "shell", 'find', "/data/app", "-iname", f"*{package_name}*"])
    output = subprocess.check_output(
        ['adb', '-s', emulator, "shell", 'find', "/data/app", "-iname", f"*{package_name}*"]).decode('utf-8')
    apkInstallPath = output.strip('\n')
    print(apkInstallPath)
    return


def getHash(ApkPath):
    hasher = hashlib.sha256()
    # Open and read file
    with open(ApkPath, 'rb') as f:
        content = f.read()
        hasher.update(content)
    return hasher.hexdigest()

def cleanupApp():
    res = subprocess.run(f"adb -s {emulator} uninstall {package_name}",
                         shell=True, capture_output=True, text=True)


def Evaluation1(full_compile=False):
    """
    Evaluation1 function for APK analysis
    
    Args:
        full_compile (bool): If True, performs full compilation and oatdump analysis.
                            If False (default), only finds APK install path.
    """
    res = subprocess.run(f"adb -s {emulator} shell uninstall {package_name}",
                         shell=True, capture_output=True, text=True)

    # Find .odex file using package_name
    output = subprocess.check_output(
        ['adb', '-s', emulator, "shell", 'find', "/data/app", "-iname", f"*{package_name}*"]).decode('utf-8')
    apkInstallPath = output.strip('\n')
    print(apkInstallPath)
    
    if not full_compile:
        return

    # Compile target Application without inline optimization
    output = subprocess.check_output(
        ['adb', '-s', emulator, "shell", 'cmd', "package", "compile", "-f", "-m", "verify", f"{package_name}"]).decode('utf-8')
    if "Success" not in output:
        print("Evaluation 1 : Compile Error in target Application")

    output = subprocess.check_output(
        ['adb', '-s', emulator, "shell", 'logcat', "-d", "|grep", "dex2oat64", "|grep", "zip-fd","|tail", "-n", "1"]).decode('utf-8')

    time.sleep(3)
    dex2oatLogcat = output.split(" ")
    print(dex2oatLogcat)
    print()
    print()
    dex2oatCommand = ['adb', '-s', emulator, "shell", "/apex/com.android.art/bin/dex2oat64"]
    dex2oatCommand.append(f"--oat-file={apkInstallPath}/oat/arm64/base.odex")
    dex2oatCommand.append(f"--dex-file={apkInstallPath}/base.apk")
    dex2oatCommand.append("--inline-max-code-units=0")
    start = False
    for argument in dex2oatLogcat:
        if ("bin/dex2oat64" in argument):
            start = True
            continue
        if (start):
            if ("-fd" in argument):
                continue
            elif ("-location" in argument):
                continue
            else:
                dex2oatCommand.append(argument)
    
    print(dex2oatCommand)
    print()
    print(output)

    # remove former evaluation setting
    res = subprocess.run(f"adb -s {emulator} shell rm /data/local/tmp/bpftools/targetBPFTRACE",
                         shell=True, capture_output=True, text=True)

    # oatdump target application
    packageName = package_name.replace('.', '_')
    res = subprocess.run(f"adb -s {emulator} shell oatdump --oat-file={apkInstallPath}/oat/arm64/base.odex --output=/data/local/tmp/{packageName}.txt",
                         shell=True, capture_output=True, text=True)
    
    hashVal = str(getHash(apk_path))
    
    # pull & store the result
    res = subprocess.run(f"adb -s {emulator} pull /data/local/tmp/{packageName}.txt {hashVal}",
                         shell=True, capture_output=True, text=True)

    # Make Symbolic link
    res = subprocess.run(f"adb -s {emulator} shell ln -s {apkInstallPath}/oat/arm64/base.odex /data/local/tmp/bpftools/targetBPFTRACE",
                         shell=True, capture_output=True, text=True)

    res = subprocess.run(f"adb -s {emulator} shell uninstall {package_name}",
                         shell=True, capture_output=True, text=True)

    print("Evaluation 1 Setting Done")


def getRootShell():
    res = subprocess.run(f"adb -s {emulator} root",
                         shell=True, capture_output=True, text=True)


if __name__ == "__main__":
    # Get emulator from environment variable
    emulator = os.environ.get('AHAFUZZ_EMULATOR', 'emulator-5554')
    
    if len(sys.argv) > 1:
        apk_path = sys.argv[1]
    else:
        apk_path = input("Input APK file: ")
    
    if not os.path.exists(apk_path):
        print(f"'{apk_path}' not exist")
        exit(1)
    
    print(f"Using emulator: {emulator}")

    getRootShell()
    # Get package name first before installation
    package_name, compile_sdk_version = get_apk_info()
    print(f"Package Name: {package_name}")
    print(f"Compile SDK Version: {compile_sdk_version}")
    
    success, message = install_apk(apk_path)
    if success:
        print("APK install success")
        print(parse_manifest_components())
        uid = get_package_uid(package_name)
        print(f"Target uid : {uid}")
        Evaluation1()
    else:
        print("APK install Failed")
