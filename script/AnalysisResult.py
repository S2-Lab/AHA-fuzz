#!/usr/bin/env python3
"""
AnalysisResult.py - AHAFuzz Result Analysis Tool

This script analyzes fuzzing results collected from an Android device, including:
- AOT (Ahead-of-Time) compiled method information
- Interpreter method execution data
- Method execution frequency and patterns
- Memory mapping and address resolution

Usage:
    python3 AnalysisResult.py [result_directory]

Arguments:
    result_directory: Directory containing fuzzing results (default: "result")

Output:
    - Report_Duplicated.txt: Detailed analysis of method execution frequencies
"""

import os
import sys
import json
import pickle
from typing import Dict, List, Tuple, Optional, Any

################################################################################
# Configuration
################################################################################

# Parse command line arguments
if len(sys.argv) > 1:
    targetDir = str(sys.argv[1])
else:
    targetDir = "result"

# File paths
mapping = f"{targetDir}/mapping.txt"
resultAddr = f"{targetDir}/result_addr.txt"
DuplicatedAnalysis = f"{targetDir}/Report_Duplicated.txt"
DrebinFeatureAnalysis = f"{targetDir}/Report_DrebinFeature.txt"
Report_FeatureReduce = f"{targetDir}/Report_FeatureReduce.txt"
SequenceAnalysis = f"{targetDir}/Report_Sequence.txt"

script_path = os.environ.get('AHAFUZZ_SCRIPT_PATH', os.path.dirname(os.path.abspath(__file__))) + "/"


################################################################################
# Parse Mapping File
################################################################################
# Open file and parse each line as JSON
with open(mapping, 'r') as file:
    mapping_entries = [json.loads(line) for line in file]

# Sort by 'base_addr' in descending order
# Convert base_addr to integer for comparison
# {"file_path": "/system/framework/arm64/boot-apache-xml.oat", "base_addr": "7039e000", "oatdata": "0000000000001000"}
mapping_entries_sorted = sorted(
    mapping_entries, key=lambda x: int(x['base_addr'], 16), reverse=True)


################################################################################
# Example code for counting duplicate lines in a .txt file using dictionary in Python
################################################################################

# Initialize dictionary to store duplicate count for each line
line_count = {}

# Open file and calculate duplicate count for each line
with open(resultAddr, 'r') as file:
    for line in file:
        cleaned_line = line.strip()  # Remove leading/trailing whitespace

        # Count line duplicates using dictionary
        if cleaned_line in line_count:
            line_count[cleaned_line] += 1
        else:
            line_count[cleaned_line] = 1

# Sort by duplicate count in descending order
sorted_line_count = sorted(
    line_count.items(), key=lambda x: x[1], reverse=True)


################################################################################
# Parse files containing method offset information
################################################################################

# Check if pkl_files subdirectory exists, otherwise use main directory
pkl_dir = f"{targetDir}/pkl_files" if os.path.exists(f"{targetDir}/pkl_files") else targetDir
fileList = os.listdir(pkl_dir)

# Filter only files starting with "tmp_HookInfo"
AOTpklFileNames = [f for f in fileList if f.startswith("tmp_HookInfo")]
AOTpklFiles = dict()

# Load pickle files
for f in AOTpklFileNames:
    with open(f"{pkl_dir}/{f}", 'rb') as file:
        AOTpklFiles[f] = pickle.load(file)


################################################################################
# Parse files containing dex_method_idx information for interpreter
################################################################################

# Use the same pkl_dir as above
fileList = os.listdir(pkl_dir)

# Filter only files starting with "tmp_MethodIdxInfo_"
IdxpklFileNames = [f for f in fileList if f.startswith("tmp_MethodIdxInfo_")]
IdxpklFiles = dict()

# Load pickle files
for f in IdxpklFileNames:
    with open(f"{pkl_dir}/{f}", 'rb') as file:
        # Fixed: Use '.oat' instead of 'oat' to avoid trailing dot
        targetName = f.split('tmp_MethodIdxInfo_')[1].split(".oat")[0]
        IdxpklFiles[targetName] = pickle.load(file)


################################################################################
# Parse Address Framework Mapping File
################################################################################

maps_Addrdata = []  # List to store parsed data as global variable
with open(f"{targetDir}/tmp_AddrFrameworkMapping.txt", 'r') as file:
    for line in file:
        range_part, file_name = line.split(' ', 1)
        start_hex, end_hex = range_part.split('-')
        start_dec = int(start_hex, 16)
        end_dec = int(end_hex, 16)
        maps_Addrdata.append((start_dec, end_dec, file_name))


def check_range(number: int) -> Optional[str]:
    """
    Check if a given number is within any range stored in the global variable.
    
    Args:
        number: Memory address to check
        
    Returns:
        File name if within range, None otherwise
    """
    for start, end, name in maps_Addrdata:
        if start <= number <= end:
            return name
    return None


################################################################################
# Output Results
################################################################################

dex_code_idx = set()
zygote_idx = set()

# Statistics for summary report
stats = {
    'aot_total': 0,
    'aot_success': 0,
    'aot_unique': 0,
    'interpreter_total': 0,
    'interpreter_success': 0,
    'interpreter_unique': 0,
    'interpreter_zygote': 0,
    'dex_total': 0,
    'dex_unique': 0,
}

# Remove existing analysis file if exists
if os.path.exists(DuplicatedAnalysis):
    os.remove(DuplicatedAnalysis)

with open(DuplicatedAnalysis, 'w') as file1:
    for line, count in sorted_line_count:
        done = False
        method_type = line.split()[0]
        addr = line.split()[1]
        lineValue = int(addr.strip().strip('\x00'), 16)
        
        if method_type == "A":
            # Process AOT compiled methods
            stats['aot_total'] += count  # Add actual execution count, not just 1
            for entry in mapping_entries_sorted:
                baseAddress = int(entry["base_addr"], 16) + \
                    int(entry["oatdata"], 16)
                
                if baseAddress < lineValue:
                    targetOAT = entry["file_path"].split('/')[-1]
                    for pklfile in AOTpklFiles:
                        if targetOAT in pklfile:
                            addrOffset = lineValue - baseAddress
                            if addrOffset in AOTpklFiles[pklfile]:
                                file1.write(
                                    f"{AOTpklFiles[pklfile][addrOffset]} : {count}\n")
                                stats['aot_success'] += count  # Add actual execution count
                                stats['aot_unique'] += 1  # Count unique method
                            done = True
                            break
                
                if done:
                    break
            
        elif method_type == "I":
            # Process methods executed in Interpreter
            stats['interpreter_total'] += count  # Add actual execution count, not just 1
            method_addr = int(addr.strip().strip('\x00'), 16)
            method_idx = line.split()[2]
            method_file = check_range(method_addr)
            
            if method_file != None:
                done = False
                # Fixed: Extract filename without path and extension for exact matching
                # Handle both .oat and .art files, and [anon:...] format
                # IMPORTANT: Strip whitespace FIRST, then remove brackets and extensions
                method_file_base = method_file.split('/')[-1].strip()  # Remove whitespace (including \n) first
                method_file_base = method_file_base.rstrip(']')  # Then remove trailing ]
                method_file_base = method_file_base.replace('.oat', '').replace('.art', '')  # Remove extensions
                
                # Try exact file matching first
                if method_file_base in IdxpklFiles:
                    if method_idx in IdxpklFiles[method_file_base]:
                        file1.write(f"{IdxpklFiles[method_file_base][method_idx]} : {count}\n")
                        stats['interpreter_success'] += count  # Add actual execution count
                        stats['interpreter_unique'] += 1  # Count unique method
                        done = True
                    else:
                        # Method not found in exact matched file
                        # For boot.art region, try all boot-* files as fallback
                        if method_file_base == 'boot' or method_file_base.startswith('boot-'):
                            for pklfile in sorted(IdxpklFiles.keys()):
                                if pklfile.startswith('boot') and pklfile != method_file_base:
                                    if method_idx in IdxpklFiles[pklfile]:
                                        file1.write(f"{IdxpklFiles[pklfile][method_idx]} : {count}\n")
                                        stats['interpreter_success'] += count  # Add actual execution count
                                        stats['interpreter_unique'] += 1  # Count unique method
                                        done = True
                                        break
                else:
                    # Exact file name not found in IdxpklFiles
                    done = False
                
            else:
                # Zygote space case
                if method_idx not in zygote_idx:
                    file1.write(f"zygote idx maybe {method_idx} {hex(method_addr)}\n")
                    zygote_idx.add(method_idx)
                # Always count zygote executions (not just unique)
                stats['interpreter_zygote'] += count  # Add actual execution count
        
        elif method_type == "M":
            # Process DEX code methods (dalvik-zygote space case => APK interpreter)
            stats['dex_total'] += count  # Add actual execution count
            method_addr = int(addr.strip().strip('\x00'), 16)
            method_idx = line.split()[2]
            
            if method_idx not in dex_code_idx:
                file1.write(f"Dex Idx {method_idx} {hex(method_addr)}\n")
                stats['dex_unique'] += 1  # Count unique method
                dex_code_idx.add(method_idx)

################################################################################
# Print Summary Report to stdout (will be redirected to AnalysisReport.txt)
################################################################################

print("=" * 80)
print("AHAFuzz Analysis Report")
print("=" * 80)
print()
print(f"Result Directory: {targetDir}")
print()
print("=" * 80)
print("Method Execution Summary by Type")
print("=" * 80)
print()

# AOT Summary
print("1. AOT (Ahead-of-Time Compiled) Methods:")
print(f"   Total executions:        {stats['aot_total']:,}")
print(f"   Successfully resolved:   {stats['aot_success']:,}")
print(f"   Unique methods:          {stats['aot_unique']:,}")
if stats['aot_total'] > 0:
    success_rate = (stats['aot_success'] / stats['aot_total']) * 100
    print(f"   Success rate:            {success_rate:.2f}%")
print()

# Interpreter Summary
print("2. Interpreter Methods:")
print(f"   Total executions:        {stats['interpreter_total']:,}")
print(f"   Successfully resolved:   {stats['interpreter_success']:,}")
print(f"   Unique methods:          {stats['interpreter_unique']:,}")
print(f"   Zygote space:            {stats['interpreter_zygote']:,}")
if stats['interpreter_total'] > 0:
    success_rate = (stats['interpreter_success'] / stats['interpreter_total']) * 100
    print(f"   Success rate:            {success_rate:.2f}%")
print()

# DEX Summary
print("3. DEX (Application) Methods:")
print(f"   Total executions:        {stats['dex_total']:,}")
print(f"   Unique methods:          {stats['dex_unique']:,}")
print()