"""
AHAFuzz Processing Module

This module provides helper functions for interacting with Android's ART runtime
and OAT files. It's crucial for AHAFuzz.py to dynamically find method offsets
for eBPF probing.

"""

import re
import sys
import subprocess
import os
import pickle

# Non-target packages to exclude from hooking
Non_target = ["/view", "/graphics", "/animation", "/widget", "/util", "/lang",
              "/log", "Log", "LoadedApk", "/display", "/window", "/os", "json", "lib",
              "icu", "ICU", "BlockGuard", "Style", "style", "Color", "color", "backup"]

# Global variables
oatdata_offset = 0
BasePath = "/data/local/tmp/"

# =============================================================================
# AOT Hooking Supporting Functions
# =============================================================================


def get_oatdump(file_name):
    file = file_name.split('/')[-1]
    targetFile = f"{BasePath}/oatdump_{file}.txt"
    if not os.path.isfile(targetFile):
        os.system(
            f"oatdump --oat-file={file_name} --output={BasePath}/oatdump_{file}.txt")
    return f"{BasePath}/oatdump_{file}.txt"


def parse_oatdump(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    data = []
    idx_data = {}
    current_class = ""
    current_method = ""
    method_info = {}
    is_dex_code = False
    dex_code_list = []

    for line in lines:
        line = line.strip()

        # Parse class name
        class_match = re.match(r'^\d+: (L[^;]+;)', line)
        if class_match:
            current_class = class_match.group(1)
            continue

        # Parse method and arguments
        method_match = re.match(r'^\d+: ([^\(]+)\(([^)]*)\)', line)
        if method_match:
            # print("method_match : " + line)
            if method_info:  # Save previous method info
                data.append(method_info)
                method_info = {}
            current_method = method_match.group(1).split()[-1]
            method_args = method_match.group(2).split(',')
            method_info = {
                "class": current_class,
                "method": current_method,
                "arguments": method_args,
                "invoke_direct": [],
                "code_offset": ""
            }

            # Get dex_method_idx
            if "dex_method_idx=" not in line:
                print("Error : cannot find dex_method_idx")
                exit()
            method_idx = line.split("dex_method_idx=")[1].split(')')[0]
            if method_idx in idx_data:
                idx_data[method_idx].append(current_method)
            else:
                idx_data[method_idx] = [current_method]

            is_dex_code = False
            continue

        # Parse DEX code
        if "DEX CODE:" in line:
            is_dex_code = True
            continue

        if is_dex_code and "invoke-direct" in line:
            invoke_direct_match = re.search(
                r'invoke-direct(/range,)?\s+{([^}]+)},\s+([^\(]+)\(([^)]*)\)', line)
            # r'invoke-direct ([^|]+)\| invoke-direct/range, ([^{]+) \{([^}]*)\}', line)
            if invoke_direct_match:
                invoked_method = invoke_direct_match.group(2).split()[-1]
                invoked_method_args = invoke_direct_match.group(3).split(',')
                dex_code_list.append({
                    "method": invoked_method,
                    "method_args": invoked_method_args
                })
            else:
                print("------ error1 -----")
                print(line)
            continue

        if is_dex_code and not line.startswith("0x"):
            method_info["invoke_direct"] = dex_code_list
            dex_code_list = []
            is_dex_code = False
            continue

        # Parse code_offset
        code_offset_match = re.match(r'^code_offset: (0x[0-9a-fA-F]+)', line)
        if code_offset_match:
            method_info["code_offset"] = code_offset_match.group(1)
            continue

    # Save last method info
    if method_info:
        data.append(method_info)

    filenameonly = filename.split('/')[-1].split('oatdump_')[1].split('.txt')[0]
    with open(f'{BasePath}/tmp_MethodIdxInfo_{filenameonly}.pkl', 'wb') as file:
        pickle.dump(idx_data, file)
    return data


def extract_invoke_direct(parsed_data):
    invoke_direct_set = set()
    for item in parsed_data:
        for invoke in item['invoke_direct']:
            method_with_args = f"{invoke['method']}({','.join(invoke['method_args'])})"
            invoke_direct_set.add(method_with_args)

    return invoke_direct_set


def coarse_grind_data(parsed_data, direct_method, filename):
    global Non_target
    data_dict = {}
    dup_dict = {}
    for item in parsed_data:
        method_with_args = f"{item['method']}({','.join(item['arguments'])})"

        if item['code_offset'] == "0x00000000":
            continue
        # Maybe this doesn't work
        if method_with_args in direct_method:
            # print(item)
            continue
        if ("<init>" in item['method'] or "<clinit>" in item['method']):
            continue

        flag = False
        for exclusion in Non_target:
            if exclusion in item['class']:
                flag = True
                break
        if (flag):
            continue

        # There would be duplicated offset value : Because of Optimization
        # Printing All duplicated data is inefficient because some cases has 100 more offset
        # So In Degging mode, Printing only one data and check duplicated in "tmp_dupdata.txt"
        if int(item['code_offset'], 16) in data_dict.keys():
            if item['code_offset'] not in dup_dict.keys():
                dup_dict[item['code_offset']] = [
                    data_dict[int(item['code_offset'], 16)]]
            dup_dict[item['code_offset']].append({
                'class': item['class'],
                'method': item['method'],
                'argument': item['arguments']
            })
            continue

        # print(item['code_offset'])
        data_dict[int(item['code_offset'], 16)] = {
            'class': item['class'],
            'method': item['method'],
            'argument': item['arguments']
        }

    # Store duplicated data
    with open(f'{BasePath}/DuplicatedData.txt', 'a') as f:
        f.write(f"----------------------")
        for item in dup_dict:
            f.write(f"Offset : {item}\n")
            for i in dup_dict[item]:
                f.write(f"{str(i)}\n")
            f.write('\n')

    # store data_dict into tmp_HookInfo
    with open(f'{BasePath}/tmp_HookInfo{filename}.pkl', 'wb') as file:
        pickle.dump(data_dict, file)
    return data_dict


############################################################
# AOT Hooking Start point
############################################################

def get_hooking(filename):
    fileOnly = filename.split('/')[-1]
    print(
        f"Get Hooking information about {BasePath}/bpftools/tmp_HookInfo{fileOnly}.pkl")
    if os.path.isfile(f"{BasePath}/bpftools/tmp_HookInfo{fileOnly}.pkl"):
        print(f"reach here, {BasePath}/bpftools/tmp_HookInfo{fileOnly}")
        with open(f"{BasePath}/bpftools/tmp_HookInfo{fileOnly}.pkl", 'rb') as file:
            return pickle.load(file)
    else:
        oatdump_file = get_oatdump(filename)
        data = parse_oatdump(oatdump_file)
        direct_method = extract_invoke_direct(data)
        return coarse_grind_data(data, direct_method, fileOnly)

############################################################
# Supporting functions
############################################################


def get_oatdata(file_name):
    if not os.path.isfile(f"{BasePath}/tmp_oatdata.txt"):
        command_oatdata = f'readelf -d -s {file_name} > {BasePath}/tmp_oatdata.txt'
        process_oatdata = subprocess.run(
            command_oatdata, shell=True, stderr=subprocess.PIPE)
        if process_oatdata.returncode != 0:
            print(f"readelf Error")
    with open(f'{BasePath}/tmp_oatdata.txt', 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 8 and parts[7] == 'oatdata':
                return parts[1]


def find_zygote():
    # find zygote pid- not optimized version
    global zygote_pid
    zygote_pid = 0

    # if not os.path.exists("/data/local/tmp/tmp_zygote.txt"):
    if not os.path.isfile(f"{BasePath}/tmp_zygote.txt"):
        command_zygote = f'ps -ef | grep zygote > {BasePath}/tmp_zygote.txt'
        process_zygote = subprocess.Popen(
            command_zygote, shell=True, stderr=subprocess.PIPE)
        out, err = process_zygote.communicate()
        if process_zygote.returncode != 0:
            print(f"zygote Error: {err}")
    with open(f'{BasePath}/tmp_zygote.txt', 'r') as file:
        for line in file:
            parts = line.split()
            if parts[7] == 'zygote' or parts[7] == 'zygote64':
                zygote_pid = parts[1]
                break
    
    # Store Address-/system/framework mapping result
    if zygote_pid != 0:
        if not os.path.isfile(f"{BasePath}/tmp_AddrFrameworkMapping.txt"):

            command_zygote = f"cat /proc/{zygote_pid}/maps |" + " grep '/system/framework/' | awk '{print $1, $6}' " +  f"> {BasePath}/tmp_AddrFrameworkMapping.txt"
            process_zygote = subprocess.Popen(
                command_zygote, shell=True, stderr=subprocess.PIPE)
            out, err = process_zygote.communicate()
            if process_zygote.returncode != 0:
                print(f"zygote Error: {err}")


    if zygote_pid != 0:
        print(f"zygote pid : {zygote_pid}")
        return zygote_pid
    else:
        print("Error : Cannot find Zygote")

# except_files parameter should be a list


def find_framework_oat(except_files=[], findOnly=""):
    global zygote_pid
    oat_list = []
    try:
        zygote_pid
    except:
        zygote_pid = find_zygote()

    # command = f"cat /proc/{zygote}/maps | grep -E '\.oat$' | grep r-xp | sed 's/.* \([^ ]*\)$/\1/' > /data/local/tmp/tmp_framework_oat.txt"

    # if not os.path.isfile(f"{BasePath}/tmp_framework_oat.txt"):
    command = f"cat /proc/{zygote_pid}/maps | grep -E '\.oat$'  > {BasePath}/tmp_framework_oat.txt"
    res = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)
    out, err = res.communicate()
    if res.returncode != 0:
        print("find framework oat error")

    if findOnly == "":
        with open(f'{BasePath}/tmp_framework_oat.txt', 'r') as file:
            tmp_set = set()
            for line in file:
                file_path = line.split()[5]
                base_addr = line.split("-")[0]
                if file_path in tmp_set:
                    continue
                else:
                    tmp_set.add(file_path)
                if except_files:
                    Find = False
                    for except_file in except_files:
                        if except_file in file_path:
                            Find = True
                            # For interpreter mapping information
                            # TODO : There will be more better ways..
                            oatdump_file = get_oatdump(file_path)
                            parse_oatdump(oatdump_file)
                            break
                    if Find:
                        continue
                tmp_list = {
                    "file_path": file_path,
                    "base_addr": base_addr
                }
                oat_list.append(tmp_list)
        return oat_list
    else:
        with open(f'{BasePath}/tmp_framework_oat.txt', 'r') as file:
            tmp_set = set()
            for line in file:
                file_path = line.split()[5]
                base_addr = line.split("-")[0]
                if findOnly in file_path:
                    return base_addr


def find_target_uid(package_name):
    if not os.path.isfile(f"{BasePath}/tmp_uid.txt"):
        command = f"dumpsys package {package_name} | grep userId > {BasePath}/tmp_uid.txt"
        res = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)
        out, err = res.communicate()
        if res.returncode != 0:
            print("find package uid error")

    with open(f'{BasePath}/tmp_uid.txt', 'r') as file:
        for line in file:
            userId = line.split("=")[-1]
            if userId.isdigit():
                return int(userId)
    print("Error : Cannot find uid")
    return -1


def getArtOffset(mangling_name):
    if not os.path.isfile(f"{BasePath}/tmp_libart.txt"):
        # TODO : Find libart.so
        command = f"readelf -s  /apex/com.android.art/lib64/libart.so > {BasePath}/tmp_libart.txt"
        res = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)
        out, err = res.communicate()
        if res.returncode != 0:
            print("find package uid error")
    with open(f"{BasePath}/tmp_libart.txt") as file:
        for line in file:
            if mangling_name in line:
                # There are two cases: " 10215:", "  3643:" => Consider these parsing cases
                if ":" in line.split(" ")[2]:
                    return int(line.split(" ")[3], 16)
                elif ":" in line.split(" ")[3]:
                    return int(line.split(" ")[4], 16)
                return int(line.split(" ")[2], 16)


# This method return multiple offset values to list type
def getArtOffsets(mangling_name):
    if not os.path.isfile(f"{BasePath}/tmp_libart.txt"):
        # TODO : Find libart.so
        command = f"readelf -s  /apex/com.android.art/lib64/libart.so > {BasePath}/tmp_libart.txt"
        res = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)
        out, err = res.communicate()
        if res.returncode != 0:
            print("find package uid error")
    returnOffsets = set()
    with open(f"{BasePath}/tmp_libart.txt") as file:
        for line in file:
            if mangling_name in line:
                if ":" in line.split(" ")[2]:
                    returnOffsets.add(int(line.split(" ")[3], 16))
                elif ":" in line.split(" ")[3]:
                    returnOffsets.add(int(line.split(" ")[4], 16))
                else:
                    returnOffsets.add(int(line.split(" ")[2], 16))
    return list(returnOffsets)

def getlibDexOffset(mangling_name):
    if not os.path.isfile(f"{BasePath}/tmp_libdexfile.txt"):
        # TODO : Find libdexfile.so
        command = f"readelf -s  /apex/com.android.art/lib64/libdexfile.so > {BasePath}/tmp_libdexfile.txt"
        res = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)
        out, err = res.communicate()
        if res.returncode != 0:
            print("find package uid error")
    with open(f"{BasePath}/tmp_libdexfile.txt") as file:
        for line in file:
            if mangling_name in line:
                # There are two cases: " 10215:", "  3643:" => Consider these parsing cases
                # print(line.split(" "))
                if ":" in line.split(" ")[2]:
                    return int(line.split(" ")[3], 16)
                elif ":" in line.split(" ")[3]:
                    return int(line.split(" ")[4], 16)
                return int(line.split(" ")[2], 16)

############################################################
# For Result Analysis
############################################################

def getFrameworkStartAddr():
    global zygote_pid
    try:
        zygote_pid
    except:
        zygote_pid = find_zygote()

    command = f"cat /proc/{zygote_pid}/maps | " + " sed -n '2p' | awk -F '-' '{print $1}'"
    return subprocess.check_output(command, shell=True, stderr=subprocess.PIPE)
    

############################################################
# For Result Analysis
############################################################

def getMaps():
    global zygote_pid
    try:
        zygote_pid
    except:
        zygote_pid = find_zygote()

    command = f"cat /proc/{zygote_pid}/maps > {BasePath}/tmp_zygote_map.txt"
    process_zygote = subprocess.run(command, shell=True, stderr=subprocess.PIPE)
    if process_zygote.returncode != 0:
        print(f"zygote Error")


############################################################
# Former implemetation
############################################################


def get_file_full_path_using_zygote(file_name):
    # find zygote pid- not optimized version
    global zygote_pid
    try:
        zygote_pid
    except:
        zygote_pid = find_zygote()
    # if(zygote_pid != 0):
    # os.system('ps -ef | grep zygote > /data/local/tmp/tmp_zygote.txt')
    # os.system('ps -ef > /data/local/tmp/tmp_zygote.txt')
    command_zygote = f'ps -ef | grep zygote > {BasePath}/tmp_zygote.txt'
    process_zygote = subprocess.run(
        command_zygote, shell=True, stderr=subprocess.PIPE)
    if process_zygote.returncode != 0:
        print(f"zygote Error")
    with open(f'{BasePath}/tmp_zygote.txt', 'r') as file:
        for line in file:
            parts = line.split()
            if parts[7] == 'zygote' or parts[7] == 'zygote64':
                zygote_pid = parts[1]
                break

    # find file's full path
    path = ""
    command_path = f'cat /proc/{zygote_pid}/maps | grep {file_name} > {BasePath}/tmp_path.txt'
    process_path = subprocess.run(
        command_path, shell=True, stderr=subprocess.PIPE)
    if process_path.returncode != 0:
        print(f"cat Error")
    with open(f'{BasePath}/tmp_path.txt', 'r') as file:
        for line in file:
            parts = line.split()
            # print(parts)
            if (len(path) == 0):
                path = parts[5]
            else:
                if (path != parts[5]):
                    print("Error - 0")
                    return
    return path


# Why we can trace jave method : What we are target for is pre-compiled method by using AOT.
# So, we can get offset value using oatdump command-line tool.
# As we know the offset, we can calculate which point we should take place uprobe.
# This method will return oat_offset + code offset value with hex

def get_method_offset(file_name, class_name, method_name):
    global oatdata_offset
    # 0. get file full path, if oatdata already allocated, then skil this step
    file_name = get_file_full_path_using_zygote(file_name)
    if oatdata_offset == 0:
        # print(file_name)
        # 1.Get oatdata offset using readelf
        # os.system(f'readelf -d -s {file_name} > /data/local/tmp/tmp_oatdata.txt')
        command_oatdata = f'readelf -d -s {file_name} > {BasePath}/tmp_oatdata.txt'
        process_oatdata = subprocess.run(
            command_oatdata, shell=True, stderr=subprocess.PIPE)
        if process_oatdata.returncode != 0:
            print(f"readelf Error")
        with open(f'{BasePath}/tmp_oatdata.txt', 'r') as file:
            for line in file:
                parts = line.split()
                # print(parts)
                if len(parts) >= 8 and parts[7] == 'oatdata':
                    oatdata_offset = parts[1]
                    break

    # 2. Get method offset using oatdump
    # ex: class name : android.content.IntentFilter
    #     method name : addAction
    # TODO : Find More Simple ways - Too many unnecessary dump
    os.system(f"oatdump --oat-file={file_name} --no-dump:vmap --no-disassemble \
    --class-filter={class_name} --method-filter={method_name}  \
    --only-keep-debug --output={BasePath}/tmp_{method_name}.txt")
    # grep code_offset > {BasePath}/tmp_{method_name}.txt")
    method_offset = 0
    with open(f'{BasePath}/tmp_{method_name}.txt', 'r') as file:
        is_target_method = False
        for line in file:
            if ("dex_method_idx" in line):
                if f"{method_name}(" in line:
                    is_target_method = True
                else:
                    is_target_method = False
            if is_target_method:
                parts = line.split()
                if not parts:
                    continue
                if parts[0] == 'code_offset:':
                    # If not compiled, skip
                    if parts[1] == "0x00000000":
                        continue
                    # print(parts)
                    method_offset = parts[1]
                    break

    # if (method_offset == 0):
    #     print(method_name)
    #     return

    if (oatdata_offset != 0 and method_offset != 0):
        return int(oatdata_offset, 16) + int(method_offset, 16)
    else:
        return None


# This method return multiple offset values to list type
def get_method_offsets(file_name, class_name, method_name):
    global oatdata_offset
    file_name = get_file_full_path_using_zygote(file_name)
    if oatdata_offset == 0:
        command_oatdata = f'readelf -d -s {file_name} > {BasePath}/tmp_oatdata.txt'
        process_oatdata = subprocess.run(
            command_oatdata, shell=True, stderr=subprocess.PIPE)
        if process_oatdata.returncode != 0:
            print(f"readelf Error")
        with open(f'{BasePath}/tmp_oatdata.txt', 'r') as file:
            for line in file:
                parts = line.split()
                # print(parts)
                if len(parts) >= 8 and parts[7] == 'oatdata':
                    oatdata_offset = parts[1]
                    break
    os.system(f"oatdump --oat-file={file_name} --no-dump:vmap --no-disassemble \
    --class-filter={class_name} --method-filter={method_name}  \
    --only-keep-debug --output={BasePath}/tmp_{method_name}.txt")
    method_offsets = set()
    with open(f'{BasePath}/tmp_{method_name}.txt', 'r') as file:
        is_target_method = False
        for line in file:
            if ("dex_method_idx" in line):
                if f"{method_name}(" in line:
                    is_target_method = True
                else:
                    is_target_method = False
            if is_target_method:
                parts = line.split()
                if not parts:
                    continue
                if parts[0] == 'code_offset:':
                    # If not compiled, skip
                    if parts[1] == "0x00000000":
                        continue
                    method_offsets.add(int(oatdata_offset, 16) + int(parts[1], 16))
    return list(method_offsets)


# hooking only one method that exactly same with input method
def get_method_offset_exact(file_name, class_name, method_name):
    global oatdata_offset
    file_name = get_file_full_path_using_zygote(file_name)
    if oatdata_offset == 0:
        command_oatdata = f'readelf -d -s {file_name} > {BasePath}/tmp_oatdata.txt'
        process_oatdata = subprocess.run(
            command_oatdata, shell=True, stderr=subprocess.PIPE)
        if process_oatdata.returncode != 0:
            print(f"readelf Error")
        with open(f'{BasePath}/tmp_oatdata.txt', 'r') as file:
            for line in file:
                parts = line.split()
                if len(parts) >= 8 and parts[7] == 'oatdata':
                    oatdata_offset = parts[1]
                    break

    os.system(f"oatdump --oat-file={file_name} --no-dump:vmap --no-disassemble \
    --class-filter={class_name} --method-filter={method_name}  \
    --only-keep-debug --output={BasePath}/tmp_{method_name}.txt")
    method_offset = 0
    with open(f'{BasePath}/tmp_{method_name}.txt', 'r') as file:
        is_target_method = False
        for line in file:
            if ("dex_method_idx" in line):
                if f"{class_name}.{method_name}(" in line:
                    is_target_method = True
                else:
                    is_target_method = False
            if is_target_method:
                parts = line.split()
                if not parts:
                    continue
                if parts[0] == 'code_offset:':
                    # If not compiled, skip
                    if parts[1] == "0x00000000":
                        continue
                    # print(parts)
                    method_offset = parts[1]
                    break

    if (oatdata_offset != 0 and method_offset != 0):
        return int(oatdata_offset, 16) + int(method_offset, 16)
    else:
        return None

# This function return first met return statement's address
def get_method_ret(file_name, class_name, method_name):
    global oatdata_offset
    file_name = get_file_full_path_using_zygote(file_name)
    if oatdata_offset == 0:
        command_oatdata = f'readelf -d -s {file_name} > {BasePath}/tmp_oatdata.txt'
        process_oatdata = subprocess.run(
            command_oatdata, shell=True, stderr=subprocess.PIPE)
        if process_oatdata.returncode != 0:
            print(f"readelf Error")
        with open(f'{BasePath}/tmp_oatdata.txt', 'r') as file:
            for line in file:
                parts = line.split()
                # print(parts)
                if len(parts) >= 8 and parts[7] == 'oatdata':
                    oatdata_offset = parts[1]
                    break

    os.system(f"oatdump --oat-file={file_name} \
    --class-filter={class_name} --method-filter={method_name}  \
    --output={BasePath}/tmp_{method_name}.txt")
    method_offset = 0
    with open(f'{BasePath}/tmp_{method_name}.txt', 'r') as file:
        for line in file:
            parts = line.split()
            if not parts:
                continue
            if len(parts) != 3:
                continue
            #   0x00220530: d65f03c0	ret
            if parts[2] == 'ret':
                method_offset = parts[0].split(":")[0]
                # print(method_offset)
                break

    if (oatdata_offset != 0 and method_offset != 0):
        return int(oatdata_offset, 16) + int(method_offset, 16)
    else:
        print("Error - 2")


# This function return multiple return statement's address
def get_method_rets(file_name, class_name, method_name):
    global oatdata_offset
    file_name = get_file_full_path_using_zygote(file_name)
    if oatdata_offset == 0:
        command_oatdata = f'readelf -d -s {file_name} > {BasePath}/tmp_oatdata.txt'
        process_oatdata = subprocess.run(
            command_oatdata, shell=True, stderr=subprocess.PIPE)
        if process_oatdata.returncode != 0:
            print(f"readelf Error")
        with open(f'{BasePath}/tmp_oatdata.txt', 'r') as file:
            for line in file:
                parts = line.split()
                # print(parts)
                if len(parts) >= 8 and parts[7] == 'oatdata':
                    oatdata_offset = parts[1]
                    break

    returnAddrs = []
    os.system(f"oatdump --oat-file={file_name} \
    --class-filter={class_name} --method-filter={method_name}  \
    --output={BasePath}/tmp_{method_name}.txt")
    method_offset = 0
    with open(f'{BasePath}/tmp_{method_name}.txt', 'r') as file:
        for line in file:
            parts = line.split()
            if not parts:
                continue
            if len(parts) != 3:
                continue
            #   0x00220530: d65f03c0	ret
            if parts[2] == 'ret':
                returnAddrs.append(parts[0].split(":")[0])

    outputAddrs = []
    for returnAddr in returnAddrs:
        if (oatdata_offset != 0 and returnAddr != 0):
            outputAddrs.append(int(oatdata_offset, 16) +
                               int(returnAddr, 16))
        else:
            print("Error - 3")
    return outputAddrs

# This function return multiple return statement's address because of the exception
def get_method_rets_exception(file_name, class_name, method_name):
    global oatdata_offset
    file_name = get_file_full_path_using_zygote(file_name)
    if oatdata_offset == 0:
        command_oatdata = f'readelf -d -s {file_name} > {BasePath}/tmp_oatdata.txt'
        process_oatdata = subprocess.run(
            command_oatdata, shell=True, stderr=subprocess.PIPE)
        if process_oatdata.returncode != 0:
            print(f"readelf Error")
        with open(f'{BasePath}/tmp_oatdata.txt', 'r') as file:
            for line in file:
                parts = line.split()
                # print(parts)
                if len(parts) >= 8 and parts[7] == 'oatdata':
                    oatdata_offset = parts[1]
                    break

    returnAddrs = []
    os.system(f"oatdump --oat-file={file_name} \
    --class-filter={class_name} --method-filter={method_name}  \
    --output={BasePath}/tmp_{method_name}.txt")
    method_offset = 0
    with open(f'{BasePath}/tmp_{method_name}.txt', 'r') as file:
        for line in file:
            parts = line.split()
            if not parts:
                continue
            # 0x002da9fc: f942827e	ldr lr, [tr, #1280] ; pDeliverException
            if parts[-1] == 'pDeliverException':
                returnAddrs.append(parts[0].split(":")[0])

    outputAddrs = []
    for returnAddr in returnAddrs:
        if (oatdata_offset != 0 and returnAddr != 0):
            outputAddrs.append(int(oatdata_offset, 16) +
                               int(returnAddr, 16))
        else:
            print("Error - 3")
    return outputAddrs

# This function return specific op location
def get_method_withOp(file_name, class_name, method_name, opcode, offset=0):
    global oatdata_offset
    file_name = get_file_full_path_using_zygote(file_name)
    if oatdata_offset == 0:
        command_oatdata = f'readelf -d -s {file_name} > {BasePath}/tmp_oatdata.txt'
        process_oatdata = subprocess.run(
            command_oatdata, shell=True, stderr=subprocess.PIPE)
        if process_oatdata.returncode != 0:
            print(f"readelf Error")
        with open(f'{BasePath}/tmp_oatdata.txt', 'r') as file:
            for line in file:
                parts = line.split()
                # print(parts)
                if len(parts) >= 8 and parts[7] == 'oatdata':
                    oatdata_offset = parts[1]
                    break

    returnAddrs = []
    os.system(f"oatdump --oat-file={file_name} \
    --class-filter={class_name} --method-filter={method_name}  \
    --output={BasePath}/tmp_{method_name}.txt")
    method_offset = 0
    with open(f'{BasePath}/tmp_{method_name}.txt', 'r') as file:
        for line in file:
            parts = line.split()
            if not parts:
                continue
            if len(parts) < 3:
                continue
            #  0x004ea00c: f90012f8	str x24, [x23, #32]
            if parts[2] == opcode:
                if offset != 0 and offset in line:
                    method_offset = parts[0].split(":")[0]
                    break

    if (oatdata_offset != 0 and method_offset != 0):
        return int(oatdata_offset, 16) + int(method_offset, 16)
    else:
        print("Error - 2")
############################################################
# For Debugging
############################################################


def print_data(parsed_data, mode=1):

    if mode == 3 or mode == 5:
        invoke_data = extract_invoke_direct(parsed_data)

    for item in parsed_data:
        method_with_args = f"{item['method']}({','.join(item['arguments'])})"

        if mode == 2 and item['code_offset'] == "0x00000000":
            continue
        if mode == 3:
            if method_with_args in invoke_data:
                continue
        if mode == 4 and ("<init>" in item['method'] or "<clinit>" in item['method']):
            continue
        if mode == 5 and (item['code_offset'] == "0x00000000" or ("<init>" in item['method'] or "<clinit>" in item['method'])):
            continue

        print(f"Class: {item['class']}")
        print(f"Method: {item['method']}")
        print(f"Arguments: {', '.join(item['arguments'])}")
        print(f"Code offset: {item['code_offset']}")
        print("-" * 50)


if __name__ == "__main__":
    print("Can you reach here?????")
    list = find_framework_oat()
    for i in list:
        print(get_oatdump(i["file_path"]))
