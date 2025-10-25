from __future__ import print_function

# Standard library imports
import os
import sys
import time
import json
import pickle
import select
import threading
import traceback
import subprocess
import ast
import ctypes

# Third-party imports
from bcc import BPF
from ctypes import Structure, c_uint, c_int, c_char
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack, unpack

# Local imports
import processing

# =============================================================================
# Configuration Constants
# =============================================================================

# File paths
BPF_PROG_PATH = "/data/local/tmp/bpftools/bpf_prog"
OAT_PATH = "/system/framework/arm64/"
BOOT_FRAMEWORK_PATH = "/system/framework/arm64/boot-framework.oat"
BOOT_OAT_PATH = "/system/framework/arm64/boot.oat"
REPORT_PATH = '/data/local/tmp/result_addr.txt'
BPF_MESSAGE_PATH = "/data/local/tmp/message/bpf_output.json"
TARGET_UID_FILE_PATH = "/data/local/tmp/bpftools/tmp_targetUID.txt"

# Lowercase aliases for compatibility with existing code
boot_framework_path = BOOT_FRAMEWORK_PATH
boot_oat_path = BOOT_OAT_PATH
oat_path = OAT_PATH

# Intent processing constants (using environment variables)
MAX_STR_COUNT = int(os.environ.get('AHFUZZ_MAX_STR_COUNT', '4'))  # Maximum number of intent filters in intent list
MAX_STR_LEN = int(os.environ.get('AHFUZZ_MAX_STR_LEN', '112'))  # Maximum length of intent string

# =============================================================================
# Global Variables
# =============================================================================

# Target application UID for filtering events
target_uid = 10158

# Intent processing metadata
# Key: runnable object address, Value: Tracing intent action
# Key-value pairs are removed in dispatchMessage
intent_buffer = {}
tmpEEAction = ""

# Coverage data storage
# Key: Intent Action, Value: Dictionary of executed data
# Value structure:
#   - "action": Intent Action (string)
#   - "init": Initialization flag (bool)
#   - "discover_new": New path discovery flag (bool)
#   - "symbol_table": Symbol table data (TBD)
Feedback_buffer = {}
manifest_buffer = set()

# Hook management
# Stores hooking addresses to prevent duplicate hooking in AOTTracer
hooking_info = set()

# Custom intent processing
custom_intent_extra_methods = set()
custom_addr = dict()

# Coverage data storage
# Used for measuring API calls between Entry and End points for selective coverage feedback
tmp_coverage_set = None

# Feedback data storage
# Used for sending updated hint strings
feedback_key_dict = dict()
feedback_value_set = set()

# Mapping information storage
mapping_list_path = "/data/local/tmp/mapping.txt"

# BPF program instance
b = None
global logFile

# Statistics and state tracking
totalCount = 0
ready_to_feedback = False

# Tracing metadata
Flag_Call = False
tracing_action = ""
target_tid = 0
main_thread = 0  # Retrieved via "dispatchMessage" - always runs in main thread (UI thread)

# Manifest intent processing
Flag_ManifestCall = False  # For manifest intent feedback
currentManifestAction = ""
total_call = 0
scheduling_call = 1000000
NonTargetManifestEvent = False
setTimer = 0

# Debug settings
print_debug = True
debug_counting = 0

# Memory management
starting_addr = 0

# Coverage tracking
gui_fuzzing_coverage = 0
intent_fuzzing_coverage = 0

# Taint analysis file handle
global TaintFile

# =============================================================================
# Logging Methods
# =============================================================================

def logging_to_file(strr):
    """Log AOT compiled code execution."""
    logFile.write("A " + str(strr))
    return

def logging_to_file_interpreter(strr):
    """Log interpreter code execution."""
    logFile.write("I " + str(strr))
    return

def logging_to_file_AppCoverage(strr):
    """Log application coverage data."""
    logFile.write("M " + str(strr))
    return

def logging_taint(strr):
    """Log taint analysis data."""
    TaintFile.write(strr + '\n')
    return

def logging_debug(strr):
    """Log debug information."""
    logFile.write(strr + '\n')


# =============================================================================
# Coverage Tracking Methods
# =============================================================================

def MethodCoverage(tid, addr):
    """Track AOT-compiled method coverage."""
    global tmp_coverage_set
    global total_call
    total_call += 1
    # Call GUI & Intent event ratio scheduling method
    if total_call > scheduling_call:
        GuiIntentScheduling()
    if Flag_ManifestCall:
        # Send Manifest Feedback when tid was changed
        if (ready_to_feedback and tid == main_thread):
            sendManifestFeedback()
    logging_to_file("0x%08x\n" % addr)

# Interpreter method coverage
def MethodCoverage_interpreter(tid, addr, idx):
    global tmp_coverage_set
    global starting_addr
    global gui_fuzzing_bitmap
    global intent_fuzzing_bitmap
    global total_call
    global ready_to_feedback
    total_call += 1
    if total_call > scheduling_call:
        GuiIntentScheduling()

    dex_method_called = False

    # in general, address 12c00000-5ac00000 is dalvik space, which is related to add code
    # 5ac00000-0xffffffff : mostly android framework
    # over 0xffffffff : external library
    # we assume that app code + android framework to AppCoverage, because
    # - if detailed hardening technique like package adapted, then app code coverage is meaningless
    # - To solve that problem, we contain android framework code to AppCoverage
    # - All android apps use framework code to run, so hardening technique cannot affect coverage of android framework

    if 0xffffffff < int(addr):
        dex_method_called = True
        logging_to_file_AppCoverage("0x%08x %i\n" % (addr, idx))
    else:
        logging_to_file_interpreter("0x%08x %i\n" % (addr, idx))
        
    if Flag_Call and (target_tid == tid):  # Not targetting to trace AOT call
        tmp_coverage_set.set_bit(idx)
        if dex_method_called:
            intent_fuzzing_bitmap.set_bit(idx)
        return

    if Flag_ManifestCall:
        tmp_coverage_set.set_bit(idx)
        if dex_method_called:
            intent_fuzzing_bitmap.set_bit(idx)
        # Send Manifest Feedback when tid was changed
        if (ready_to_feedback and tid == main_thread):
            sendManifestFeedback()
    if dex_method_called:
        gui_fuzzing_bitmap.set_bit(idx)


#########################################################
##                     AOT Tracing                     ##
#########################################################


def print_AOTTracer(cpu, data, size):
    event = b["AOTTrace"].event(data)
    MethodCoverage(event.tid, event.addr)


def AOTTracer_probe_set():
    # oat_list = processing.find_framework_oat()
    # The reason why we except boot.oat : boot.oat has fundamental jave operations like equal(). 
    # Tracking all basic operations is meaningless to observe application behavior
    oat_list = processing.find_framework_oat(except_files=["boot.oat"])
    total_cnt = 0
    cnt = 1

    for oat_file in oat_list:
        file_path = oat_file["file_path"]
        hooking_offset = processing.get_hooking(file_path)
        oatdata = processing.get_oatdata(file_path)
        oat_file['oatdata'] = oatdata
        total_cnt += len(hooking_offset)
        for item in hooking_offset:
            hooking_addr = int(item) + int(oatdata, 16)
            if hooking_addr in hooking_info:
                continue
            b.attach_uprobe(
                name=file_path, addr=hooking_addr, fn_name="AOTTracer")
            cnt += 1
    # This operation record the mapping result of oat files.
    # That file will be used in generating result.
    with open(mapping_list_path, "w", encoding="utf-8") as file:
        for item in oat_list:
            file.write(json.dumps(item, ensure_ascii=False))
            file.write('\n')


def AOTTracer():
    AOTTracer_probe_set()
    b["AOTTrace"].open_perf_buffer(print_AOTTracer, page_cnt=4096)


#########################################################
##                 Interperter Tracing                 ##
#########################################################
    
# There are 3 main ways to execute code through Interpreter;
# 1. MTERP : Machine TERP
    # NterpGetMethod(Thread*, ArtMethod* ..)
    # NterpGetStaticField(Thread*, ArtMethod* ..)
    # NterpGetInstanceFieldOffset(Thread*, ArtMethod* ..)
    # NterpGetClassOrAllocateObject(Thread*, ArtMethod* ..)
    # NterpLoadObject(Thread*, ArtMethod* ..)
    # Actual executing the interpreter code is not above method, written in assembly code.
    # But to invoke method, interpreter should run above method to get method informations.
# 2. No MTERP - ArtMethod::Invoke()
    # art_quick_invoke_stub(ArtMethod* ..)
    # art_quick_invoke_static_stub(ArtMethod* ..)
# 3. No MTERP - Interpreter::Execute()
    # ExecuteSwitchImplAsm(&ctx...)
        # .self
        # .accessor
        # shadow_frame
            # link
            # method_

def print_MterpInterpreterTracer(cpu, data, size):
    event = b["MterpInterpreterTrace"].event(data)
    MethodCoverage_interpreter(event.tid, event.method_head, event.method_idx)


def print_InvokeInterpreterTracer(cpu, data, size):
    event = b["InvokeInterpreterTrace"].event(data)
    MethodCoverage_interpreter(event.tid, event.method_head, event.method_idx)

def print_ExecuteInterpreterTracer(cpu, data, size):
    event = b["ExecuteInterpreterTrace"].event(data)
    MethodCoverage_interpreter(event.tid, event.method_head, event.method_idx)

def InterpreterTracer():

    # 1. MTERP : Machine TERP
        # NterpGetMethod(Thread*, ArtMethod* ..)
        # NterpGetStaticField(Thread*, ArtMethod* ..)
        # NterpGetInstanceFieldOffset(Thread*, ArtMethod* ..)
        # NterpGetClassOrAllocateObject(Thread*, ArtMethod* ..)
        # NterpLoadObject(Thread*, ArtMethod* ..)
    # Interpreter_MTERP = [
    #     "NterpGetMethod",
    #     "NterpGetStaticField",
    #     "NterpGetInstanceFieldOffset",
    #     "NterpGetClassOrAllocateObject",
    #     "NterpLoadObject",
    # ]
    Interpreter_MTERP = [
        "nterp_op_invoke_virtual",
        "nterp_op_invoke_super",
        "nterp_op_invoke_direct",
        "nterp_op_invoke_interface",
        "nterp_op_invoke_virtual_range",
        "nterp_op_invoke_super_range",
        "nterp_op_invoke_direct_range",
        "nterp_op_invoke_interface_range",
        "nterp_op_invoke_polymorphic",
        "nterp_op_invoke_polymorphic_range",
        "nterp_op_invoke_custom",
        "nterp_op_invoke_custom_range",
        "nterp_op_invoke_static",
        "nterp_op_invoke_static_range",
    ]
    for MTERP in Interpreter_MTERP:
        execute_offset = processing.getArtOffset(MTERP)
        b.attach_uprobe(name="/apex/com.android.art/lib64/libart.so",
                        addr=execute_offset,
                        fn_name="MterpInterpreterTracer")

    # 2. No MTERP - ArtMethod::Invoke()
        # art_quick_invoke_stub(ArtMethod* ..)
        # art_quick_invoke_static_stub(ArtMethod* ..)
    Interpreter_Invoke = [
        "art_quick_invoke_stub",
        "art_quick_invoke_static_stub",
    ]
    for Invoke in Interpreter_Invoke:
        execute_offset = processing.getArtOffset(Invoke)
        b.attach_uprobe(name="/apex/com.android.art/lib64/libart.so",
                        addr=execute_offset,
                        fn_name="InvokeInterpreterTracer")

    # 3. No MTERP - Interpreter::Execute()
        # ExecuteSwitchImplAsm(&ctx...)
            # .self
            # .accessor
            # shadow_frame
                # link
                # method_
        
    execute_offset = processing.getArtOffset("ExecuteSwitchImplAsm")
    b.attach_uprobe(name="/apex/com.android.art/lib64/libart.so",
                    addr=execute_offset,
                    fn_name="ExecuteInterpreterTracer")

    b["MterpInterpreterTrace"].open_perf_buffer(
        print_MterpInterpreterTracer, page_cnt=2048)
    b["InvokeInterpreterTrace"].open_perf_buffer(
        print_InvokeInterpreterTracer, page_cnt=512)
    b["ExecuteInterpreterTrace"].open_perf_buffer(
        print_ExecuteInterpreterTracer, page_cnt=512)
        


#########################################################
##               Manifest Intent Tracing               ##
#########################################################

def print_ManifestReceiver(cpu, data, size):
    global Flag_ManifestCall
    global currentManifestAction
    global NonTargetManifestEvent
    global tmp_coverage_set
    global ready_to_feedback

    event = b["handleReceiverTrace"].event(data)
    str_len = int(event.bit_lens) // 2
    message = event.strs[:str_len].decode("utf-8")

    if not message in manifest_buffer:
        NonTargetManifestEvent = True
        if print_debug:
            print(f"[WARN] Unknown intent: {message}")
        return

    if Flag_ManifestCall:
        if ready_to_feedback:
            sendManifestFeedback()
        else:
            if print_debug:
                if currentManifestAction == message:
                    print(f"[ERROR] Duplicate intent: {message}")
                else:
                    print(f"[ERROR] Intent collision: {currentManifestAction} → {message}")
            clearManifestFeedback()
            return

    ready_to_feedback = False
    tmp_coverage_set = BitArray(65536)
    Flag_ManifestCall = True
    currentManifestAction = message

    if print_debug:
        print(f"[Manifest] {message}")


def print_ManifestService(cpu, data, size):
    global Flag_ManifestCall
    global currentManifestAction
    global NonTargetManifestEvent
    global tmp_coverage_set
    global ready_to_feedback

    if print_debug:
        global debug_counting
        debug_counting = total_call

    event = b["handleServiceArgsTrace"].event(data)
    str_len = int(event.bit_lens) // 2
    message = event.strs[:str_len].decode("utf-8")

    if not message in manifest_buffer:
        NonTargetManifestEvent = True
        if print_debug:
            print(f"[WARN] Unknown service: {message}")
        return

    if Flag_ManifestCall:
        if currentManifestAction == message:
            if print_debug:
                print(f"[ERROR] Duplicate service: {message}")
            return
        if print_debug:
            print(f"[ERROR] Service collision: {currentManifestAction} → {message}")
        clearManifestFeedback()

    ready_to_feedback = False
    tmp_coverage_set = BitArray(65536)
    Flag_ManifestCall = True
    currentManifestAction = message

    if print_debug:
        print(f"[Service] {message}")


def print_ManifestRet(cpu, data, size):
    global Flag_ManifestCall
    global currentManifestAction
    global NonTargetManifestEvent
    global tmp_coverage_set
    global ready_to_feedback
    event = b["ManifestRetTrace"].event(data)

    if NonTargetManifestEvent:
        NonTargetManifestEvent = False
        return

    if Flag_ManifestCall:
        ready_to_feedback = True
        # sendManifestFeedback()


def ManifestTracer():
    # void android.app.ActivityThread.handleReceiver(android.app.ActivityThread$ReceiverData) (dex_method_idx=4382)
    broadcastReceiver_addr = processing.get_method_offset_exact("boot-framework.oat", "android.app.ActivityThread", "handleReceiver")

    broadcastReceiver_ret_addrs = processing.get_method_rets("boot-framework.oat", "android.app.ActivityThread", "handleReceiver")
    broadcastReceiver_exception_addrs = processing.get_method_rets_exception("boot-framework.oat", "android.app.ActivityThread", "handleReceiver")

    # void android.app.ActivityThread.handleServiceArgs(android.app.ActivityThread$ServiceArgsData) (dex_method_idx=4385)
    service_addr = processing.get_method_offset_exact("boot-framework.oat",
                                                      "android.app.ActivityThread", "handleServiceArgs")
    service_ret_addrs = processing.get_method_rets("boot-framework.oat",
                                                  "android.app.ActivityThread", "handleServiceArgs")
    service_exception_addrs = processing.get_method_rets_exception("boot-framework.oat",
                                                  "android.app.ActivityThread", "handleServiceArgs")

    # *onBind(), unBind() is out of scope - not related to the intent event

    hooking_info.add(broadcastReceiver_addr)
    for addr in broadcastReceiver_ret_addrs:
        hooking_info.add(addr)

    
    for addr in broadcastReceiver_exception_addrs:
        hooking_info.add(addr)

    hooking_info.add(service_addr)
    for addr in service_ret_addrs:
        hooking_info.add(addr)
    for addr in service_exception_addrs:
        hooking_info.add(addr)

    b.attach_uprobe(name="/system/framework/arm64/boot-framework.oat",
                    addr=broadcastReceiver_addr, fn_name="handleReceiverTracer")
    for addr in broadcastReceiver_ret_addrs:
        b.attach_uprobe(name="/system/framework/arm64/boot-framework.oat",
                        addr=addr, fn_name="ManifestRetTracer")
    for addr in broadcastReceiver_exception_addrs:
        b.attach_uprobe(name="/system/framework/arm64/boot-framework.oat",
                        addr=addr, fn_name="ManifestRetTracer")

    b.attach_uprobe(name="/system/framework/arm64/boot-framework.oat",
                    addr=service_addr, fn_name="handleServiceArgsTracer")
    for addr in service_ret_addrs:
        b.attach_uprobe(name="/system/framework/arm64/boot-framework.oat",
                        addr=addr, fn_name="ManifestRetTracer")
    for addr in service_exception_addrs:
        b.attach_uprobe(name="/system/framework/arm64/boot-framework.oat",
                        addr=addr, fn_name="ManifestRetTracer")

    b["handleReceiverTrace"].open_perf_buffer(print_ManifestReceiver, page_cnt=32)
    b["handleServiceArgsTrace"].open_perf_buffer(print_ManifestService, page_cnt=32)
    b["ManifestRetTrace"].open_perf_buffer(print_ManifestRet, page_cnt=32)


#########################################################
##                 coverage scheduling                 ##
#########################################################

class BitArray:
    def __init__(self, size):
        self.size = size
        self.array = [0] * ((size + 31) // 32)

    def set_bit(self, index):
        if index >= self.size or index < 0:
            raise IndexError("Index out of range")
        self.array[index // 32] |= (1 << (index % 32))

    def count_ones(self):
        count = 0
        for value in self.array:
            count += bin(value).count('1')
        return count

    def count_common_ones(self, other):
        if self.size != other.size:
            raise ValueError("BitArrays must be of the same size")

        common_count = 0
        for val1, val2 in zip(self.array, other.array):
            common_count += bin(val1 & val2).count('1')
        return common_count

    def or_with(self, other):
        if self.size != other.size:
            raise ValueError("BitArrays must be of the same size")

        result = BitArray(self.size)
        for i in range(len(self.array)):
            result.array[i] = self.array[i] | other.array[i]
        return result
    
    def discoverNew(self, other):
        # count_ones + count_common_ones
        if self.size != other.size:
            raise ValueError("BitArrays must be of the same size")
        target_count = 0
        common_count = 0
        for val1, val2 in zip(self.array, other.array):
            target_count += bin(val1).count('1')
            common_count += bin(val1 & val2).count('1')
        return target_count - common_count



#########################################################
##              RegisterReceiver Tracing               ##
#########################################################


class data_RR(Structure):
    _fields_ = [
        ("tid", c_uint),
        ("strs", c_char * MAX_STR_LEN * MAX_STR_COUNT),
        ("total_len", c_int),
        ("bit_lens", c_int * MAX_STR_COUNT),
        ("broadcastreceiver", c_int),
    ]

def print_registerReceiver(cpu, data, size):
    global Feedback_buffer
    event = ctypes.cast(data, ctypes.POINTER(data_RR)).contents
    event_list = []
    total_len = event.total_len
    if (total_len > MAX_STR_COUNT):
        if print_debug:
            print(f"[WARN] Intent overflow: {total_len} > {MAX_STR_COUNT}")
        total_len = MAX_STR_COUNT
    for i in range(total_len):
        str_len = int(event.bit_lens[i]) // 2
        try:
            action = event.strs[i][:str_len].decode("utf-8")
        except:
            if print_debug:
                print(f"[ERROR] Decode error: len={str_len}")
        event_list.append(action)

    for event_act in event_list:
        if not event_act in Feedback_buffer:
            Feedback_buffer[event_act] = {
                "symbol_table": {},
                "hint_table": set()
            }
        send_messege_init(event_act)


def registerReceiverTracer():
    register_addr = processing.get_method_offset("boot-framework.oat",
                                                 "android.app.ContextImpl", "registerReceiverInternal")
    hooking_info.add(register_addr)

    b.attach_uprobe(name="/system/framework/arm64/boot-framework.oat",
                    addr=register_addr, fn_name="registerReceiverTracer")

    b["registerReceiverTrace"].open_perf_buffer(print_registerReceiver, page_cnt=32)


#########################################################
##             Sending Feedback to Fuzzer              ##
#########################################################

def getHintTable(action):
    global feedback_value_set
    global Feedback_buffer
    if mode == "AHAFuzzS":
        feedback_dict = {}
        return feedback_dict
    feedback_set = feedback_value_set - Feedback_buffer[action]["hint_table"]
    Feedback_buffer[action]["hint_table"] = Feedback_buffer[action]["hint_table"] | feedback_set
    
    feedback_dict = {}
    for hintStr in feedback_set:
        if type(hintStr) == tuple:
            if (hintStr[0] == hintStr[1]):
                feedback_dict[hintStr[0]] = 1
            else:
                feedback_dict[hintStr[0] + '|Candidate|' + hintStr[1]] = 2
        else:
            feedback_dict[hintStr] = 1

    feedback_value_set = set()
    return feedback_dict

def updateKeyTable(action):
    global feedback_key_dict
    global Feedback_buffer
    Feedback_buffer[action]["symbol_table"].update(feedback_key_dict)
    feedback_key_dict = dict()
    return

def send_messege_init(action):
    global totalCount
    totalCount += 1
    event_data = {"action": action, "init": "False",
                  "discover_new": 0, "symbol_table": {},"hint_table": {}, "count": totalCount}
    with open(BPF_MESSAGE_PATH, 'a') as f:
        if print_debug:
            print(f"[Register] {action}")
        f.write(json.dumps(event_data))
        f.write("\n")


def send_feedback(action):
    global totalCount
    global Feedback_buffer
    totalCount += 1
    updateKeyTable(action)
    if len(Feedback_buffer[action]["symbol_table"]) == 0:
        feedback_table = {}
    else:
        feedback_table = getHintTable(action)
    event_data = {"action": action, "init": "False",
                  "discover_new": Feedback_buffer[action]["discover_new"],
                  "symbol_table": Feedback_buffer[action]["symbol_table"],
                  "hint_table": feedback_table,
                  "count": totalCount}
    with open(BPF_MESSAGE_PATH, 'a') as f:
        if print_debug:
            print(f"[Feedback] {action}: +{Feedback_buffer[action]['discover_new']} edges")
        f.write(json.dumps(event_data))
        f.write("\n")


def sendManifestFeedback():
    global Flag_ManifestCall
    global totalCount
    global currentManifestAction
    global ready_to_feedback
    global Feedback_buffer
    
    action = currentManifestAction
    currentManifestAction = ""
    Flag_ManifestCall = False
    ready_to_feedback = False
    totalCount += 1

    updateKeyTable(action)
    feedback_table = getHintTable(action)

    if not "coverage" in Feedback_buffer[action]:
        Feedback_buffer[action]["coverage"] = tmp_coverage_set
        Feedback_buffer[action]["discover_new"] = tmp_coverage_set.count_ones()
    else:
        discover_new = tmp_coverage_set.discoverNew(Feedback_buffer[action]["coverage"])
        Feedback_buffer[action]["discover_new"] = discover_new
        Feedback_buffer[action]["coverage"] = Feedback_buffer[action]["coverage"].or_with(tmp_coverage_set)

    event_data = {"action": action, "init": "False",
                  "discover_new": Feedback_buffer[action]["discover_new"],
                  "symbol_table": Feedback_buffer[action]["symbol_table"],
                    "hint_table": feedback_table,
                  "count": totalCount}
    with open(BPF_MESSAGE_PATH, 'a') as f:
        if print_debug:
            print(f"[Manifest Feedback] {action}: +{Feedback_buffer[action]['discover_new']} edges, {len(Feedback_buffer[action]['symbol_table'])} symbols, {len(feedback_table)} hints")
        f.write(json.dumps(event_data))
        f.write("\n")

# error handling 
def clearManifestFeedback():
    global Flag_ManifestCall
    global currentManifestAction
    global feedback_value_set
    global feedback_key_dict

    currentManifestAction = ""
    Flag_ManifestCall = False
    feedback_value_set = set()
    feedback_key_dict = dict()

def clearDynamicReceiverFeedback():
    global Flag_Call
    global tracing_action
    global feedback_value_set
    global feedback_key_dict

    tracing_action = ""
    Flag_Call = False
    feedback_value_set = set()
    feedback_key_dict = dict()

def GuiIntentScheduling():
    global gui_fuzzing_bitmap
    global intent_fuzzing_bitmap
    global gui_fuzzing_coverage
    global intent_fuzzing_coverage
    global total_call

    total_call = 0

    gui_fuzzing_coverage = gui_fuzzing_bitmap.count_ones() - gui_fuzzing_coverage
    intent_fuzzing_coverage = intent_fuzzing_bitmap.count_ones() - intent_fuzzing_coverage

    total = gui_fuzzing_coverage + intent_fuzzing_coverage
    if total == 0:
        intent_ratio = 50
    else:
        intent_ratio = (intent_fuzzing_coverage / total) * 100

    event_data = {"action": "GuiIntentScheduling", "init": "False",
                  "discover_new": 0,
                  "symbol_table": {},
                    "hint_table": {},
                  "count": intent_ratio}

    if print_debug:
        print(f"[Scheduling] Intent ratio: {intent_ratio:.1f}%")
    with open(BPF_MESSAGE_PATH, 'a') as f:
        f.write(json.dumps(event_data))
        f.write("\n")


#########################################################
##            Entrypoint & Endpoint Tracing            ##
#########################################################


def performReceive_called(cpu, data, size):
    global tmpEEAction
    event = b["IntentTrace"].event(data)
    str_len = int(event.bit_lens) // 2
    message = event.strs[:str_len].decode("utf-8")
    if not message in Feedback_buffer:
        return
    if tmpEEAction != "" and Flag_Call == True:
        if print_debug:
            print(f"[ERROR] Intent collision: {tmpEEAction} → {message}")
    tmpEEAction = message
    if print_debug:
        print(f"[Dynamic] {message}")



def Message_called(cpu, data, size):
    global intent_buffer
    global tracing_action
    global tmpEEAction
    global main_thread
    event = b["MessageTrace"].event(data)
    main_thread = event.tid

    if (tmpEEAction != ""):
        tracing_action = tmpEEAction
        tmpEEAction = ""
        global Flag_Call
        global target_tid
        global tmp_coverage_set
        Flag_Call = True
        target_tid = event.tid
        tmp_coverage_set = BitArray(65536)
        return


def finishReceiver_called(cpu, data, size):
    global Flag_Call
    global tracing_action
    global target_tid
    global Feedback_buffer
    global tmp_coverage_set

    if Flag_Call == False:
        return
    Flag_Call = False
    target_tid = 0
    tmp_action = tracing_action
    tracing_action = ""
    if not "coverage" in Feedback_buffer[tmp_action]:
        Feedback_buffer[tmp_action]["coverage"] = tmp_coverage_set
        Feedback_buffer[tmp_action]["discover_new"] = tmp_coverage_set.count_ones()
    else:
        discover_new = tmp_coverage_set.discoverNew(Feedback_buffer[tmp_action]["coverage"])
        Feedback_buffer[tmp_action]["discover_new"] = discover_new
        Feedback_buffer[tmp_action]["coverage"] = Feedback_buffer[tmp_action]["coverage"].or_with(tmp_coverage_set)
    send_feedback(tmp_action)


def EntryEndTracer():
    performReceiveAddr = processing.get_method_offset("boot-framework.oat","android.app.LoadedApk$ReceiverDispatcher", "performReceive")


    dispatchMessageAddr = processing.get_method_offset("boot-framework.oat",
                                                       "android.os.Handler", "dispatchMessage")

    finishReceiverAddr = processing.get_method_rets(
        "boot-framework.oat", "android.os.Handler", "dispatchMessage")  # get_method_rets return list
    finishReceiverAddr.append(processing.get_method_offset("boot-framework.oat",
                                                           "android.app.IActivityManager$Stub$Proxy", "finishReceiver"))

    b.attach_uprobe(name=boot_framework_path,
                    addr=performReceiveAddr, fn_name="IntentTracer")
    hooking_info.add(performReceiveAddr)

    b.attach_uprobe(name=boot_framework_path,
                    addr=dispatchMessageAddr, fn_name="MessageTracer")
    hooking_info.add(dispatchMessageAddr)

    for finishAddr in finishReceiverAddr:
        b.attach_uprobe(name=boot_framework_path,
                        addr=finishAddr, fn_name="FinTracer")
        hooking_info.add(finishAddr)

    b["IntentTrace"].open_perf_buffer(performReceive_called, page_cnt=32)
    b["MessageTrace"].open_perf_buffer(Message_called, page_cnt=32)
    b["FinTrace"].open_perf_buffer(finishReceiver_called, page_cnt=32)

#########################################################
##               Custom Intent Feedback                ##
#########################################################


def CustomTracerCalled(cpu, data, size):
    global Feedback_buffer
    event = b["CustomTrace"].event(data)
    MethodCoverage(event.tid, event.addr)

    if Flag_Call or Flag_ManifestCall:
        if Flag_Call:
            target_action = tracing_action
        else:
            target_action = currentManifestAction

        str_len = int(event.bit_lens) // 2
        if str_len == 0:
            return
        HintString = event.strs[:str_len].decode("utf-8")

        methodName = custom_addr.get(event.addr, "")
        if methodName != "":
            feedback_key_dict[HintString] = methodName
        else:
            feedback_value_set.add(HintString)
            

def CustomDDTracerCalled(cpu, data, size):
    global Feedback_buffer
    event = b["CustomDDTrace"].event(data)
    MethodCoverage(event.tid, event.addr)
    if Flag_Call or Flag_ManifestCall:
        if Flag_Call:
            target_action = tracing_action
        else:
            target_action = currentManifestAction

        str_len1 = int(event.bit_lens1) // 2
        str_len2 = int(event.bit_lens2) // 2
        valid_str1 = False
        valid_str2 = False
        if (str_len1 != 0 and (len(event.strs1) >= str_len1)):
            valid_str1 = True
        if (str_len2 != 0 and (len(event.strs2) >= str_len2)):
            valid_str2 = True
        if (valid_str1 and valid_str2):
            try:
                HintString1 = event.strs1[:str_len1].decode("utf-8")
                HintString2 = event.strs2[:str_len2].decode("utf-8")
                feedback_value_set.add((HintString1, HintString2))
                return
            except:
                return
        elif valid_str1:
            try:
                HintString1 = event.strs1[:str_len1].decode("utf-8")
                feedback_value_set.add(HintString1)
                return
            except:
                return
        elif valid_str2:
            try:
                HintString2 = event.strs2[:str_len2].decode("utf-8")
                feedback_value_set.add(HintString2)
                return
            except:
                return



def CustomIntentTracer():
    # Use custom_intent_extra_methods, custom_addr
    # # custom intent 구분하는 dictionary
    # custom_intent_extra_methods = set => Hooking method name
    # custom_addr = dict() => Key : Hooked Address, Value : Hooking method name
    custom_intent_extra_methods = {
        "getBooleanArrayExtra",
        "getBundleExtra",
        "getByteArrayExtra",
        "getCharArrayExtra",
        "getCharSequenceArrayExtra",
        "getCharSequenceArrayListExtra",
        "getCharSequenceExtra",
        "getDoubleArrayExtra",
        "getFloatArrayExtra",
        "getIBinderExtra",
        "getIntArrayExtra",
        "getIntegerArrayListExtra",
        "getLongArrayExtra",
        "getShortArrayExtra",
        "getStringArrayExtra",
        "getStringArrayListExtra",
        "getStringExtra",
        "hasCategory",
        "hasExtra",
        "getBooleanExtra",
        "getByteExtra",
        "getCharExtra",
        "getDoubleExtra",
        "getFloatExtra",
        "getIntExtra",
        "getLongExtra",
        "getParcelableArrayExtra",
        "getParcelableArrayListExtra",
        "getParcelableExtra",
        "getSerializableExtra",
        "getShortExtra",
        "getDataString",
    }

    # Some of the cases, it changes intent to bundle, and get extra values
    custom_intent_bundle_methods = {
        "get",
        "getArrayList",
        "getBoolean",
        "getBooleanArray",
        "getByte",
        "getByteArray",
        "getChar",
        "getCharArray",
        "getCharSequence",
        "getCharSequenceArray",
        "getCharSequenceArrayList",
        "getDouble",
        "getDoubleArray",
        "getFloat",
        "getFloatArray",
        "getInt",
        "getIntArray",
        "getIntegerArrayList",
        "getLong",
        "getLongArray",
        "getSerializable",
        "getShort",
        "getShortArray",
        "getString",
        "getStringArray",
        "getStringArrayList",
        "getValue",
        "remove",
    }

    recoding_methods_1st_str = { # First Argument = java.lang.String
        "java.lang.AbstractStringBuilder.indexOf",
        "java.lang.AbstractStringBuilder.lastIndexOf",
        "java.lang.String.indexOf",
        "java.lang.String.lastIndexOf",
        "java.lang.StringBuffer.indexOf",
        "java.lang.StringBuffer.lastIndexOf",
    }

    recoding_methods_self_and_1st_str = { # this, First Argument = java.lang.String
        "java.lang.String.equals",
        "java.lang.String.equalsIgnoreCase",
        "java.lang.String.contains",
        "java.lang.String.contentEquals",
        "java.lang.String.endsWith",
        "java.lang.String.matches",
        "java.lang.String.startsWith",
        "java.lang.String.compareTo",
    }

    frameworkOffsetAddr = processing.find_framework_oat(
        findOnly="boot-framework.oat")

    # For intent-class related custom feedback
    for methodName in custom_intent_extra_methods:
        method_offset = processing.get_method_offset(
            "boot-framework.oat", "android.content.Intent", methodName)
        if method_offset == None:
            continue
        b.attach_uprobe(name=boot_framework_path,
                        addr=method_offset, fn_name="CustomTracer")
        hooking_info.add(method_offset)
        custom_addr[int(frameworkOffsetAddr, 16) + method_offset] = methodName
        
    # For intent-class related custom feedback
    for methodName in custom_intent_bundle_methods:
        method_offsets = processing.get_method_offsets(
            "boot-framework.oat", "android.os.BaseBundle", methodName)
        for method_offset in method_offsets:
            if method_offset == None:
                continue
            b.attach_uprobe(name=boot_framework_path, addr=method_offset, fn_name="CustomTracer")
            hooking_info.add(method_offset)
            custom_addr[int(frameworkOffsetAddr, 16) + method_offset] = methodName
            
    # For recording primitive values
    for methodClass in recoding_methods_1st_str:
        ClassAndMethod = methodClass.rsplit('.', 1)
        className = ClassAndMethod[0]
        methodName = ClassAndMethod[1]
        method_offsets = processing.get_method_offsets("boot.oat", className, methodName)
        for method_offset in method_offsets:
            if method_offset == None:
                continue
            b.attach_uprobe(name=boot_oat_path,
                            addr=method_offset, fn_name="CustomTracer")
            
    # For recording primitive values
    for methodClass in recoding_methods_self_and_1st_str:
        ClassAndMethod = methodClass.rsplit('.', 1)
        className = ClassAndMethod[0]
        methodName = ClassAndMethod[1]
        method_offsets = processing.get_method_offsets("boot.oat", className, methodName)
        for method_offset in method_offsets:
            if method_offset == None:
                continue
            b.attach_uprobe(name=boot_oat_path,
                            addr=method_offset, fn_name="CustomDDTracer")
    
    b["CustomTrace"].open_perf_buffer(CustomTracerCalled, page_cnt=64)
    b["CustomDDTrace"].open_perf_buffer(CustomDDTracerCalled, page_cnt=64)

#########################################################
##                     Scheduling                      ##
#########################################################

def JobSchedulerTracerCalled(cpu, data, size):
    event = b["JobSchedulerTrace"].event(data)
    if print_debug:
        print(f"[Schedule] JobScheduler fast-forward: {event.latency / 60000:.1f}min")

def postDelayedTracerCalled(cpu, data, size):
    event = b["postDelayedTrace"].event(data)
    if print_debug:
        print(f"[Schedule] PostDelayed fast-forward: {event.diff / 60000:.1f}min")

def SchedulerTracer():
    # android.app.job.JobInfo$Builder.setMinimumLatency
    JobSchedulerAddr = processing.get_method_ret("boot-framework.oat", "android.app.job.JobInfo$Builder", "setMinimumLatency")

    # boolean android.os.MessageQueue.enqueueMessage(android.os.Message, long) -> long : Scheduling time
    #   0x004ea008: b90032e0	str w0, [x23, #48]
    #   0x004ea00c: f90012f8	str x24, [x23, #32] <<-- Change Latency informations, [x23, #32] == latency
    #   0x004ea010: 1000007e	adr lr, #+0xc (addr 0x4ea01c) <<-- Hooking Here, and overwrite x24 value to (Clock + Target_Latency)
    postDelayedAddr = processing.get_method_withOp("boot-framework.oat", "android.os.MessageQueue", "enqueueMessage", "str", "#32")

    # Note : AHAFuzz can cover AlarmManager, because AlarmManager works with dynamically registered intent

    hooking_info.add(JobSchedulerAddr)
    hooking_info.add(postDelayedAddr)

    b.attach_uprobe(name="/system/framework/arm64/boot-framework.oat",
                    addr=JobSchedulerAddr, fn_name="JobSchedulerTracer")
    b.attach_uprobe(name="/system/framework/arm64/boot-framework.oat",
                    addr=postDelayedAddr, fn_name="postDelayedTracer")

    b["JobSchedulerTrace"].open_perf_buffer(
        JobSchedulerTracerCalled, page_cnt=32)
    b["postDelayedTrace"].open_perf_buffer(
        postDelayedTracerCalled, page_cnt=32)

#########################################################
##            Method-level taint analysis              ##
#########################################################

def SourceStrTracercalled(cpu, data, size):
    event = b["SourceStrTrace"].event(data)
    str_len = int(event.bit_lens) // 2
    if str_len == 0:
        return
    SourceStr = event.strs[:str_len].decode("utf-8", errors="replace")
    logging_taint(str(event.addr) + SourceStr)

def SourcePrivTracercalled(cpu, data, size):
    event = b["SourcePrivTrace"].event(data)
    logging_taint(str(event.addr) + str(event.priv))

def Sink1stTracercalled(cpu, data, size):
    event = b["Sink1stTrace"].event(data)
    str_len = int(event.bit_lens) // 2
    if str_len == 0:
        logging_taint(str(event.addr) + str(event.priv))
    else:
        SinkStr = event.strs[:str_len].decode("utf-8", errors="replace")
        logging_taint(str(event.addr) + SinkStr)

def Sink2ndTracercalled(cpu, data, size):
    event = b["Sink2ndTrace"].event(data)
    str_len = int(event.bit_lens) // 2
    if str_len == 0:
        logging_taint(str(event.addr) + str(event.priv))
    else:
        SinkStr = event.strs[:str_len].decode("utf-8", errors="replace")
        logging_taint(str(event.addr) + SinkStr)

def Sink3rdTracercalled(cpu, data, size):
    event = b["Sink3rdTrace"].event(data)
    str_len = int(event.bit_lens) // 2
    if str_len == 0:
        logging_taint(str(event.addr) + str(event.priv))
    else:
        SinkStr = event.strs[:str_len].decode("utf-8", errors="replace")
        logging_taint(str(event.addr) + SinkStr)

def PropagateInputTracercalled(cpu, data, size):
    event = b["PropagateInputTrace"].event(data)
    str_len = int(event.bit_lens) // 2
    if str_len == 0:
        logging_taint("I" + str(event.addr) + str(event.priv))
    else:
        SinkStr = event.strs[:str_len].decode("utf-8", errors="replace")
        logging_taint("I" + str(event.addr) + SinkStr)

def PropagateOutputTracercalled(cpu, data, size):
    event = b["PropagateOutputTrace"].event(data)
    str_len = int(event.bit_lens) // 2
    if str_len == 0:
        logging_taint("O" + str(event.addr) + str(event.priv))
    else:
        SinkStr = event.strs[:str_len].decode("utf-8", errors="replace")
        logging_taint("O" + str(event.addr) + SinkStr)

def MethodTaintAnalysis():
    sourceFile = open("/data/local/tmp/bpftools/Source.txt", 'r')
    for line in sourceFile:
        # boot.oat java.io.File java.lang.String getPath 
        info = line.split()
        oat_file = info[0]
        class_name = info[1]
        ret_type = info[2]
        method_name = info[3]
        if ret_type == "java.lang.String":
            addrs = processing.get_method_rets(oat_file, class_name, method_name)
            for addr in addrs:
                if addr in hooking_info:
                    continue
                hooking_info.add(addr)
                b.attach_uprobe(name=oat_path + oat_file ,addr=addr, fn_name="SourceStrTracer")
                b["SourceStrTrace"].open_perf_buffer(SourceStrTracercalled, page_cnt=256)
        else:
            addrs = processing.get_method_rets(oat_file, class_name, method_name)
            for addr in addrs:
                if addr in hooking_info:
                    continue
                hooking_info.add(addr)
                b.attach_uprobe(name=oat_path + oat_file ,addr=addr, fn_name="SourcePrivTracer")
                b["SourcePrivTrace"].open_perf_buffer(SourcePrivTracercalled, page_cnt=64)


    sinkFile = open("/data/local/tmp/bpftools/Sink.txt", 'r')
    for line in sinkFile:
        # boot.framework.oat android.os.Bundle void putByte 2
        info = line.split()
        oat_file = info[0]
        class_name = info[1]
        ret_type = info[2]
        method_name = info[3]
        argu_index = info[4]
        if argu_index == "1":
            addrs = processing.get_method_offsets(oat_file, class_name, method_name)
            for addr in addrs:
                if addr in hooking_info:
                    continue
                hooking_info.add(addr)
                b.attach_uprobe(name=oat_path + oat_file ,addr=addr, fn_name="Sink1stTracer")
                b["Sink1stTrace"].open_perf_buffer(Sink1stTracercalled, page_cnt=256)
        elif argu_index == "2":
            addrs = processing.get_method_offsets(oat_file, class_name, method_name)
            for addr in addrs:
                if addr in hooking_info:
                    continue
                hooking_info.add(addr)
                b.attach_uprobe(name=oat_path + oat_file ,addr=addr, fn_name="Sink2ndTracer")
                b["Sink2ndTrace"].open_perf_buffer(Sink2ndTracercalled, page_cnt=256)
        else:
            addrs = processing.get_method_offsets(oat_file, class_name, method_name)
            for addr in addrs:
                if addr in hooking_info:
                    continue
                hooking_info.add(addr)
                b.attach_uprobe(name=oat_path + oat_file ,addr=addr, fn_name="Sink3rdTracer")
                b["Sink3rdTrace"].open_perf_buffer(Sink3rdTracercalled, page_cnt=256)

    propagateFile = open("/data/local/tmp/bpftools/Propagate.txt", 'r')
    for line in propagateFile:
        info = line.split()
        class_name = info[1]
        method_name = info[2]
        input_addrs = processing.get_method_offsets("boot.oat", class_name, method_name)
        output_addrs = processing.get_method_rets("boot.oat", class_name, method_name)
        for addr in input_addrs:
            if addr in hooking_info:
                continue
            hooking_info.add(addr)
            b.attach_uprobe(name=boot_oat_path ,addr=addr, fn_name="PropagateInputTracer")
            b["PropagateInputTrace"].open_perf_buffer(PropagateInputTracercalled, page_cnt=256)
        for addr in output_addrs:
            if addr in hooking_info:
                continue
            hooking_info.add(addr)
            b.attach_uprobe(name=boot_oat_path ,addr=addr, fn_name="PropagateOutputTracer")
            b["PropagateOutputTrace"].open_perf_buffer(PropagateOutputTracercalled, page_cnt=256)



#########################################################
##                    Clean & Main                     ##
#########################################################

def register_static():
    global Feedback_buffer
    if os.path.isfile(BPF_MESSAGE_PATH):
        count = 0
        with open(BPF_MESSAGE_PATH, 'r') as file:
            for line in file:
                obj = json.loads(line)
                target_action = obj["action"]
                if target_action == "Explicit_Intent":
                    target_action = obj["name"]
                if not target_action in Feedback_buffer:
                    Feedback_buffer[target_action] = {
                        "symbol_table": {},
                        "hint_table": set()
                    }
                manifest_buffer.add(target_action)
                count += 1
        if print_debug:
            print(f"[Init] Registered {count} manifest intents")
    else:
        if print_debug:
            print("[Init] No manifest file, creating new")
        kk = open(BPF_MESSAGE_PATH, 'w')
        kk.close()


if __name__ == "__main__":

    if len(sys.argv) > 1:
        mode = str(sys.argv[1])
    else:
        mode = "AHAFuzz"

    if os.path.isfile(TARGET_UID_FILE_PATH):
        with open(TARGET_UID_FILE_PATH, 'r') as uidFile:
            target_uid = int(uidFile.read())
        print(f"[Init] Target UID: {target_uid}")
    else:
        print("[Init] No UID file, using default: 1000")
        target_uid = 1000

    target_latency = int(os.environ.get('AHFUZZ_TARGET_LATENCY', '1000000'))
    
    if print_debug:
        print(f"[Init] Mode: {mode}")
        print(f"[Init] Target latency: {target_latency/1000000:.1f}s")

    logFile = open(REPORT_PATH, 'a') 
    logFile1 = open("/data/local/tmp/tmp.txt", 'a') 
    TaintFile = open('/data/local/tmp/taint_result.txt', 'a') 

    # 65536's dex indexed : GUI/Intent ratio scheduling
    gui_fuzzing_bitmap = BitArray(65536)
    intent_fuzzing_bitmap = BitArray(65536)

    with open(f"{BPF_PROG_PATH}/AHAFuzzTracer_bpf.c") as bpf_file:
        bpf_text = bpf_file.read()
        bpf_text = bpf_text.replace("TARGET_UID", str(target_uid))
        bpf_text = bpf_text.replace("TARGET_LATENCY", str(target_latency))
        bpf_text = bpf_text.replace("set:MAX_STR_LEN", str(MAX_STR_LEN))
        bpf_text = bpf_text.replace("set:MAX_STR_COUNT", str(MAX_STR_COUNT))
    b = BPF(text=bpf_text)

    try:
        if print_debug:
            print("[Init] Loading tracers...")
            
        if(mode == "AHAFuzz"):
            register_static()
            ManifestTracer()
            registerReceiverTracer()
            CustomIntentTracer()
            EntryEndTracer()
            SchedulerTracer()
            InterpreterTracer()
            AOTTracer()
        elif(mode == "AHAFuzzS"):
            register_static()
            ManifestTracer()
            registerReceiverTracer()
            CustomIntentTracer()
            EntryEndTracer()
            SchedulerTracer()
            InterpreterTracer()
            AntiAnalysis()
        else:
            AOTTracer()
            pass

    except Exception as e:
        print(f"[ERROR] Initialization failed: {e}")
        traceback.print_exc()
        
    print("\n" + "="*80)
    print("AHAFuzz Tracer Ready")
    print("="*80)
    
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n[Exit] AHAFuzz stopped")
            exit()