import os
import re
import json
import sys

# =============================================================================
# CONSTANTS
# =============================================================================

# Field type constants
FIELD_TYPE_OBJECT = "obj"
FIELD_TYPE_BOOLEAN = "bool" 
FIELD_TYPE_PRIMITIVE = "pri"
FIELD_TYPE_NONE = "NONE"

# Analysis result indices
RESULT_OFFSET_INDEX = 0
RESULT_TYPE_INDEX = 1
RESULT_INFERENCE_INDEX = 2
RESULT_REGISTER_INDEX = 3

# Debug message constants
DEBUG_CASE_DIRECT_LOAD = "=== Direct Load Mapping ==="
DEBUG_CASE_INFERENCE_LOAD = "=== Inference Load Mapping ==="
DEBUG_CASE_DIRECT_STORE = "=== Direct Store Mapping ==="
DEBUG_CASE_INFERENCE_STORE = "=== Inference Store Mapping ==="

# Debug control
DEBUG_ENABLED = True  # Set to False to disable debug messages

# Inference algorithm descriptions
# 1. recursively_check(): Two-pass recursive elimination algorithm
#    - Pass 1: Direct mapping for single-element candidates
#    - Pass 2: Elimination of known mappings from multi-element candidates
#
# 2. reduce_inference(): Intersection-based candidate reduction
#    - Uses set intersection to find common candidates across multiple attempts
#    - Eliminates inconsistent candidates that cannot be valid offsets
#
# 3. exclusive_assignment_inference(): Exclusive assignment principle
#    - Uses set difference to exclude other fields' candidates
#    - Assumes each field must have a unique offset (mutual exclusivity)

# =============================================================================
# DEBUG UTILITIES
# =============================================================================

def debug_print(message, category="INFO"):
    """
    Print debug message only if DEBUG_ENABLED is True.
    
    Args:
        message: The debug message to print
        category: Category of debug message (INFO, LOAD, STORE, CLEAR, etc.)
    """
    if DEBUG_ENABLED:
        print(f"[DEBUG-{category}] {message}")

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================

MemoryLayout = dict()
arithmeticInstr = {"adrp", "add", "sub", "subs", "cmn", "smull", "scvtf",
                   "msub", "sdiv", "fmul", "cvtzs", "fcvtzs", "fsub", "fabs", "fdiv",
                   "fadd", "adr", "uxth", "madd", "fcvt", "mul", "neg", "sxtb", "fmin",
                   "fmax", "smulh", "fcvtzu", "frinta", "cinc", "fsqrt", "adds", "sxth",
                   "fcvtas", "csinv", "frintp", "frintm", "fcvtas", "negs", "fneg", "dup",
                   "ands", }
logicalInstr = {"mov", "lsr", "movk", "eor", "and", "orr", "asr", "fmov", "lsl",
                "uxtb", "tst", "bic", }
branchInstr = {"blr", "bl", 'b', "cbnz", "cbz", "ret", "b.ne", "b.ge", "b.lo",
               "b.eq", "b.hs", "tbnz", "b.lt", "b.gt", "tbz", "b.le", "b.hi",
               "br", "b.ls", }
conditionInstr = {"cmp", "csel", "cset", "csinc",
                  "ccmp", "fcmp", "fcsel", "cneg", "csneg", "csetm"}
BitInstr = {"sxtw", "clz", "rbit"}
systemInstr = {"dmb", "brk", "udf", }
addressingInstr = {"ldr", "str", "ldp", "strb", "stlr", "stp", "stlxr", "ldaxr",
                   "ldrb", "ldar", "stur", "stxr", "ldxr", "ldrh", "ldur", "ldarb",
                   "stlrb", "ldrsb", "strh", "ldrsh"}
ldInstr = {"ldr", "ldur", "ldrh", "ldar", "ldrb"} # except "ldp" since only used in stack access
stInstr = {"str", "stur", "strh", "star", "strb", "stlr"} # except "stp" since only used in stack access
targetInstr = set()


currentClassName = ""
booleanList = set()

def findClassInfo(targetClass, fileOffset):
    """
    Parse target class information from offset file and initialize memory layout.
    
    Args:
        targetClass: Target class name (e.g., "android.content.Intent")
        fileOffset: Path to offset file containing class structure information
    """
    global currentClassName
    with open(fileOffset, "r") as f:
        for line in f:
            if "class: " in line:
                className = line.split("class: ")[1].strip()
                if className == targetClass:
                    target = True
                    MemoryLayout[className] = {}
                    currentClassName = className
                else:
                    target = False
            elif target:
                if "inheritance: " in line:
                    inheritance = line.split("inheritance: ")[1].strip()
                    # MemoryLayout[currentClassName]["inheritance"] = {
                    #     inheritance}
                elif "MemberVariable: " in line:
                    VariableInfo = line.strip().split(
                        "MemberVariable: ")[1].split()
                    variableName = VariableInfo[-1]
                    variableType = VariableInfo[-2]
                    primitives = ["int", "boolean", "float", "long", "byte", "short", "double", "byte", "char"]
                    if "[]" in variableType:
                        variableType = FIELD_TYPE_OBJECT
                    elif variableType == "boolean":
                        variableType = FIELD_TYPE_PRIMITIVE
                        booleanList.add(variableName)
                    elif variableType in primitives:
                        variableType = FIELD_TYPE_PRIMITIVE
                    elif "java." in variableType:
                        variableType = FIELD_TYPE_OBJECT
                    elif "android." in variableType:
                        variableType = FIELD_TYPE_OBJECT
                    else:
                        variableType = FIELD_TYPE_OBJECT
                    # MemoryLayout[currentClassName][variableName] = [
                    #     variableType]
                    access = ["public", "private", "protected"]
                    nonaccess = ["final"]
                    ignore = ["static"]
                    passField = False
                    for info in VariableInfo[:-2]:
                        if info in ignore:
                            passField = True
                        elif info in access:
                            # MemoryLayout[currentClassName]['access'] = info
                            pass
                        elif info in nonaccess:
                            continue
                        else:
                            debug_print(f"Unrecognized field modifier in line: {line.strip()}", "WARNING")
                    if not passField:
                        MemoryLayout[currentClassName][variableName] = FIELD_TYPE_NONE


startDex = False
startASM = False
currentFunc = ""
getObj = []
loadInstr = []
targetRegisters = ["x1", "w1"]
sp_pattern = r"\[sp, #\d+\]"
# targetRegisters = ["r1"]
stored_stack = []


diff_target = 0
target0 = dict()
target1 = dict()
diff = [target0, target1]


def clearInfo():
    """
    Clear all analysis state variables for next function analysis.
    
    This function resets all global variables used during the analysis
    of a single function to prepare for analyzing the next function.
    """
    global startDex
    global startASM
    global currentFunc
    global getObj
    global loadInstr
    global focusTarget
    global get_havetoFind
    global set_havetoFind
    global inferencing
    global ldResult
    global stResult
    global before_instr
    global end_addr
    global stored_stack
    global offsetAddedRegister
    
    debug_print("//////////////////////", "CLEAR")
    debug_print("Clear information", "CLEAR")
    debug_print("//////////////////////", "CLEAR")
    startDex = False
    startASM = False
    currentFunc = ""
    getObj = []
    loadInstr = []
    focusTarget = []
    get_havetoFind = dict()  # key = register , value = list
    set_havetoFind = dict()  # key = register , value = list
    inferencing = False
    ldResult = []
    stResult = []
    offsetAddedRegister = dict()
    before_instr = ""
    end_addr = ""
    stored_stack = []

directMapping = set()

def count_register_fields():
    """Count the number of load and store registers and fields."""
    cnt_ldreg = 0
    cnt_streg = 0
    
    # Count load registers and fields
    field_list = set()
    for ldreg in get_havetoFind:
        for tmpcn in get_havetoFind[ldreg]:
            field_list.add(tmpcn)
    cnt_ldreg += len(field_list)
    cnt_ldreg += len(ldResult)
    
    # Count store registers and fields
    field_list = set()
    for streg in set_havetoFind:
        for tmpcn in set_havetoFind[streg]:
            field_list.add(tmpcn)
    cnt_streg += len(field_list)
    cnt_streg += len(stResult)
    
    return cnt_ldreg, cnt_streg

def extract_object_offsets(results):
    """Extract object offsets from analysis results."""
    offsets = set()
    for result in results:
        if result[RESULT_TYPE_INDEX] == FIELD_TYPE_OBJECT:
            offsets.add(result[RESULT_OFFSET_INDEX])
    return offsets

def extract_register_number(register_str):
    """
    Extract register number from register string (e.g., "x1," -> "1", "w15" -> "15").
    
    Args:
        register_str: Register string like "x1,", "w15", "x23,"
        
    Returns:
        Register number as string, or None if invalid format
    """
    try:
        # Remove trailing comma if present
        reg_clean = register_str.rstrip(',')
        
        # Check for x register pattern (x followed by digits)
        if reg_clean.startswith('x') and reg_clean[1:].isdigit():
            return reg_clean[1:]
        # Check for w register pattern (w followed by digits)  
        elif reg_clean.startswith('w') and reg_clean[1:].isdigit():
            return reg_clean[1:]
        else:
            debug_print(f"Invalid register format: {register_str}", "WARNING")
            return None
    except (IndexError, AttributeError):
        debug_print(f"Error parsing register: {register_str}", "WARNING")
        return None

def extract_boolean_offsets(results):
    """Extract boolean offsets from analysis results."""
    offsets = set()
    if len(booleanList) != 0:
        for result in results:
            if result[RESULT_TYPE_INDEX] == FIELD_TYPE_BOOLEAN:
                offsets.add(result[RESULT_OFFSET_INDEX])
    return offsets

def exportOutput():
    """
    Export analysis results and update memory layout with found offsets.
    
    This function processes the collected load and store results from the
    current function analysis and updates the global memory layout dictionary
    with the determined field offsets.
    """
    global MemoryLayout
    global get_havetoFind
    global set_havetoFind

    # Extract load and store offsets using helper functions
    ldoffset = extract_object_offsets(ldResult)
    stoffset = extract_object_offsets(stResult)
    
    # Count registers and fields
    cnt_ldreg, cnt_streg = count_register_fields()

    # Extract boolean field offsets using helper functions
    ldBoolean = extract_boolean_offsets(ldResult)
    stBoolean = extract_boolean_offsets(stResult)

    for ld in range(len(ldResult)):
        offset = ldResult[ld][RESULT_OFFSET_INDEX]
        typeinfo = ldResult[ld][RESULT_TYPE_INDEX]
        inference = ldResult[ld][RESULT_INFERENCE_INDEX]
        targetReg = ldResult[ld][RESULT_REGISTER_INDEX]
        # if inference == False or (cnt_ldreg == 2):
        if inference == False:
            debug_print(f"Register counts - Store: {cnt_streg}, Load: {cnt_ldreg}", "LOAD")
            debug_print(DEBUG_CASE_DIRECT_LOAD, "LOAD")
            debug_print(f"Get fields to find: {get_havetoFind}", "LOAD")
            debug_print(f"Load result: {ldResult}", "LOAD")
            debug_print(f"Target register: {targetReg}", "LOAD")
            debug_print(f"Current class: {currentClassName}", "LOAD")
            if len(get_havetoFind[targetReg]) != 0:
                found_fielid = get_havetoFind[targetReg].pop(0)
                debug_print(f"Found field ID: {found_fielid}", "LOAD")
                debug_print(f"Current memory layout: {MemoryLayout[currentClassName][found_fielid]}", "LOAD")
                if MemoryLayout[currentClassName][found_fielid] != FIELD_TYPE_NONE:
                    if type(MemoryLayout[currentClassName][found_fielid]) == list:
                        inner_found = False
                        for inner_set in MemoryLayout[currentClassName][found_fielid]:
                            for val in inner_set:
                                if val == offset:
                                    inner_found = True
                                    MemoryLayout[currentClassName][found_fielid] = offset
                        if inner_found:
                            continue
                    if MemoryLayout[currentClassName][found_fielid] != offset:
                        debug_print(f"Overwriting direct values - stored: {MemoryLayout[currentClassName][found_fielid]}, current: {offset} - switching to inference", "LOAD")
                        MemoryLayout[currentClassName][found_fielid] = offset
                        # MemoryLayout[currentClassName][found_fielid].add(offset)
                MemoryLayout[currentClassName][found_fielid] = offset
        # elif (cnt_streg == 0 and len(ldoffset) == )
        else:
            debug_print(DEBUG_CASE_INFERENCE_LOAD, "LOAD")
            debug_print(f"Get fields to find: {get_havetoFind}", "LOAD")
            debug_print(f"Load result: {ldResult}", "LOAD")
            debug_print(f"Target register: {targetReg}", "LOAD")
            if len(get_havetoFind[targetReg]) != 0:
                found_fielid = get_havetoFind[targetReg].pop(0)
                if not found_fielid in MemoryLayout[currentClassName]:
                    debug_print(f"Key error: {found_fielid}", "LOAD")
                    continue
                if found_fielid in booleanList:
                    if len(ldBoolean) == 0:
                        continue
                    if MemoryLayout[currentClassName][found_fielid] == FIELD_TYPE_NONE:
                        MemoryLayout[currentClassName][found_fielid] = [ldBoolean]
                    elif type(MemoryLayout[currentClassName][found_fielid]) == str:
                        if MemoryLayout[currentClassName][found_fielid] not in ldBoolean:
                            debug_print(f"Direct mapping warning - stored: {MemoryLayout[currentClassName][found_fielid]}, current: {ldBoolean} - switching to inference", "LOAD")
                            # Create new set with string value and all elements from ldBoolean set
                            new_candidates = {MemoryLayout[currentClassName][found_fielid]}
                            new_candidates.update(ldBoolean)
                            MemoryLayout[currentClassName][found_fielid] = [new_candidates]
                        continue
                    else:
                        MemoryLayout[currentClassName][found_fielid].append(ldBoolean)

                elif MemoryLayout[currentClassName][found_fielid] == "NONE":
                    MemoryLayout[currentClassName
                                 ][found_fielid] = [ldoffset]
                elif type(MemoryLayout[currentClassName][found_fielid]) == str:
                    if MemoryLayout[currentClassName][found_fielid] not in ldoffset:
                        debug_print(f"Direct mapping warning - stored: {MemoryLayout[currentClassName][found_fielid]}, current: {ldoffset} - switching to inference", "LOAD")
                        # Create new set with string value and all elements from ldoffset set
                        new_candidates = {MemoryLayout[currentClassName][found_fielid]}
                        new_candidates.update(ldoffset)
                        MemoryLayout[currentClassName][found_fielid] = [new_candidates]
                    continue
                else:
                    MemoryLayout[currentClassName][found_fielid].append(ldoffset)
    for st in range(len(stResult)):
        offset = stResult[st][RESULT_OFFSET_INDEX]
        typeinfo = stResult[st][RESULT_TYPE_INDEX]
        inference = stResult[st][RESULT_INFERENCE_INDEX]
        targetReg = stResult[st][RESULT_REGISTER_INDEX]
        # if inference == False or (cnt_streg == 2):
        if inference == False:
            debug_print(DEBUG_CASE_DIRECT_STORE, "STORE")
            debug_print(f"Set fields to find: {set_havetoFind}", "STORE")
            debug_print(f"Store result: {stResult}", "STORE")
            debug_print(f"Target register: {targetReg}", "STORE")
            debug_print(f"Current class: {currentClassName}", "STORE")
            if len(set_havetoFind[targetReg]) != 0:
                found_fielid = set_havetoFind[targetReg].pop(0)
                debug_print(f"Found field ID: {found_fielid}", "STORE")
                debug_print(f"Current memory layout: {MemoryLayout[currentClassName][found_fielid]}", "STORE")
                if MemoryLayout[currentClassName][found_fielid] != FIELD_TYPE_NONE:
                    if type(MemoryLayout[currentClassName][found_fielid]) == list:
                        inner_found = False
                        for inner_set in MemoryLayout[currentClassName][found_fielid]:
                            for val in inner_set:
                                if val == offset:
                                    inner_found = True
                                    MemoryLayout[currentClassName][found_fielid] = offset
                        if inner_found:
                            continue
                    if MemoryLayout[currentClassName][found_fielid] != offset:
                        debug_print(f"Overwriting direct values - stored: {MemoryLayout[currentClassName][found_fielid]}, current: {offset} - switching to inference", "LOAD")
                        MemoryLayout[currentClassName][found_fielid] = offset
                        # MemoryLayout[currentClassName][found_fielid].add(offset)
                MemoryLayout[currentClassName][found_fielid] = offset
        else:
            debug_print(DEBUG_CASE_INFERENCE_STORE, "STORE")
            debug_print(f"Set fields to find: {set_havetoFind}", "STORE")
            debug_print(f"Store result: {stResult}", "STORE")
            debug_print(f"Target register: {targetReg}", "STORE")
            if len(set_havetoFind[targetReg]) != 0:
                found_fielid = set_havetoFind[targetReg].pop(0)
                if not found_fielid in MemoryLayout[currentClassName]:
                    debug_print(f"Key error: {found_fielid}", "LOAD")
                    continue
                if found_fielid in booleanList:
                    if len(stBoolean) == 0:
                        continue
                    if MemoryLayout[currentClassName][found_fielid] == FIELD_TYPE_NONE:
                        MemoryLayout[currentClassName][found_fielid] = [stBoolean]
                    elif type(MemoryLayout[currentClassName][found_fielid]) == str:
                        if MemoryLayout[currentClassName][found_fielid] not in stBoolean:
                            debug_print(f"Direct mapping warning - stored: {MemoryLayout[currentClassName][found_fielid]}, current: {stBoolean} - switching to inference", "STORE")
                            # Create new set with string value and all elements from stBoolean set
                            new_candidates = {MemoryLayout[currentClassName][found_fielid]}
                            new_candidates.update(stBoolean)
                            MemoryLayout[currentClassName][found_fielid] = [new_candidates]
                        continue
                    else:
                        MemoryLayout[currentClassName][found_fielid].append(stBoolean)

                elif MemoryLayout[currentClassName][found_fielid] == "NONE":
                    MemoryLayout[currentClassName
                                 ][found_fielid] = [stoffset]
                elif type(MemoryLayout[currentClassName][found_fielid]) == str:
                    if MemoryLayout[currentClassName][found_fielid] not in stoffset:
                        debug_print(f"Direct mapping warning - stored: {MemoryLayout[currentClassName][found_fielid]}, current: {stoffset} - switching to inference", "STORE")
                        # Create new set with string value and all elements from stoffset set
                        new_candidates = {MemoryLayout[currentClassName][found_fielid]}
                        new_candidates.update(stoffset)
                        MemoryLayout[currentClassName][found_fielid] = [new_candidates]
                    continue
                else:
                    MemoryLayout[currentClassName][found_fielid].append(stoffset)

    debug_print(f"Load results: {ldResult}", "LOAD")
    debug_print(f"Store results: {stResult}", "STORE")
    debug_print(f"Final memory layout: {MemoryLayout[currentClassName]}", "RESULT")
    clearInfo()

def printDebug(info):
    """Legacy debug function - now uses the new debug_print."""
    debug_print(info)

focusTarget = []
get_havetoFind = dict()  # key = register , value = list
set_havetoFind = dict()  # key = register , value = list
targetRegister = dict()  # key = register , value = list
offsetAddedRegister = dict() # key = pattern , value = offset
ldResult = []
stResult = []


def FindingLayoutInfo(file, target_class=None):
    global currentClassName
    global startDex
    global startASM
    global currentFunc
    global getObj
    global loadInstr
    global focusTarget
    global get_havetoFind
    global set_havetoFind
    global targetRegister
    global offsetAddedRegister
    global targetInstr
    global inferencing
    global ldResult
    global stResult
    global before_instr
    global end_addr
    global stored_stack
    # Set target class
    if target_class is not None:
        currentClassName = target_class
        debug_print(f"Analyzing target class: {target_class}", "CLASS")
    else:
        debug_print(f"Using existing target class: {currentClassName}", "CLASS")
    
    targetC = currentClassName.replace('.','/') + ';'
    startClass = False
    with open(file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # 3700: Landroid/content/Intent; (offset=0x00024bcc) (type_idx=2869) (VerifiedNeedsAccessChecks) (SomeCompiled)
            if ("(type_idx=" in line) : # class name in oatdump
                if targetC in line:
                    debug_print(f"Find target class: {line.strip()}", "CLASS")
                    startClass = True
                else:
                    if startClass:
                        exportOutput()
                        clearInfo()
                    startClass = False

            if not startClass:
                if "dex_method_idx" in line:
                    if startDex:
                        exportOutput()
                    args = [arg.strip().split(')')[0] for arg in line.split('(')[1].split(',')]
                    for arg in range(len(args)):
                        if currentClassName == args[arg]:
                            startDex = True
                            focusTarget.append(arg + 2)
                if startDex and ("iget" in line or "iput" in line):
                    objInfo = line.split('|')[1].split("//")[0]
                    objClass = '.'.join(objInfo.split()[-1].split('.')[:-1])
                    objField = objInfo.split()[-1].split('.')[-1]
                    if objClass == currentClassName: # objclass = 1, 2, 3..
                        debug_print(f"Field access - Info: {objInfo}, Class: {objClass}, Field: {objField}", "FIELD")
                        if "iget" in line:
                            for cn in focusTarget:
                                if cn not in get_havetoFind:
                                    get_havetoFind[cn] = [objField]
                                else:
                                    if objField not in get_havetoFind[cn]:
                                        get_havetoFind[cn].append(objField)
                        else:
                            for cn in focusTarget:
                                if cn not in set_havetoFind:
                                    set_havetoFind[cn] = [objField]
                                else:
                                    if objField not in set_havetoFind[cn]:
                                        set_havetoFind[cn].append(objField)
                        debug_print("Field access pattern detected", "FIELD")

            if startClass:
                if "dex_method_idx" in line:
                    if startDex:
                        exportOutput()
                    clearInfo()
                    currentFunc = " ".join(line.split(':')[1].split()[:-1])
                    currentClass = ".".join(currentFunc.split()[1].split('(')[0].split('.')[:-1])
                    args = [arg.strip().split(')')[0] for arg in line.split('(')[1].split(',')]
                    startDex = True
                    if currentClass in MemoryLayout:
                        focusTarget.append(1)
                        startDex = True
                    for arg in range(len(args)):
                        debug_print(f"Method arguments: {args}", "METHOD")
                        if args[arg] in MemoryLayout:
                            focusTarget.append(arg + 2)
                    debug_print(f"Focus targets: {focusTarget}", "METHOD")

                if startDex and ("iget" in line or "iput" in line):
                    objInfo = line.split('|')[1].split("//")[0]
                    objClass = '.'.join(objInfo.split()[-1].split('.')[:-1])
                    objField = objInfo.split()[-1].split('.')[-1]
                    debug_print(f"Field access - Info: {objInfo}, Class: {objClass}, Field: {objField}", "FIELD")
                    if objClass == currentClassName: # objclass = 1, 2, 3..
                        if "iget" in line:
                            for cn in focusTarget:
                                if cn not in get_havetoFind:
                                    get_havetoFind[cn] = [objField]
                                else:
                                    if objField not in get_havetoFind[cn]:
                                        get_havetoFind[cn].append(objField)
                        else:
                            for cn in focusTarget:
                                if cn not in set_havetoFind:
                                    set_havetoFind[cn] = [objField]
                                else:
                                    if objField not in set_havetoFind[cn]:
                                        set_havetoFind[cn].append(objField)
                        
            if startDex and "code_offset" in line:
                if "0x00000000" in line:
                    clearInfo()
                else:
                    if get_havetoFind == {} and set_havetoFind == {}:
                        clearInfo()
                        pass
                    else:
                        for key in get_havetoFind:
                            # targetRegister[key] = [fr"\b(r{key})(?!\d)"]
                            targetRegister[key] = [fr"\b(x{key}|w{key})(?!\d)"]
                        for key in set_havetoFind:
                            # targetRegister[key] = [fr"\b(r{key})(?!\d)"]
                            targetRegister[key] = [fr"\b(x{key}|w{key})(?!\d)"]
                        # pattern = r"\b(x1|w1)(?!\d)"
            if startDex and "CODE: (code_offset=" in line:
                startASM = True
                debug_print(f"Code line: {line}", "ASM")
                debug_print(f"Current function: {currentFunc}", "ASM")
                debug_print(f"Focus targets: {focusTarget}", "ASM")
                debug_print(f"Target registers: {targetRegister}", "ASM")
                debug_print(f"Get fields to find: {get_havetoFind}", "ASM")
                debug_print(f"Set fields to find: {set_havetoFind}", "ASM")
                start_addr = int(line.split("code_offset=")[1].split()[0],16)
                code_size = int(line.split("size=")[1].split(')')[0])
                end_addr = str(hex(start_addr + code_size -4))
                debug_print(f"End address: {end_addr}", "ASM")


            if startASM and ("InlineInfo" in line or "StackMap" in line):
                continue
            if startASM:
                if not line.strip().startswith('0x') or "unallocated" in line:
                    continue
                instrInfo = " ".join(line.split(':')[1].split()[1:])
                debug_print(f"Instruction: {line.strip()} | {instrInfo}", "ASM")
                instr = instrInfo.split()[0].strip()
                if instr in conditionInstr or instr in branchInstr:
                    debug_print("Found branch/condition instruction", "ASM")
                    if "addr" in line:
                        jmp_addr = line.split("addr ")[1].split(')')[0]
                        debug_print(f"Jump address: {jmp_addr}, end address: {end_addr}", "ASM")
                        if jmp_addr == end_addr:
                            debug_print("Skip jump (end of function)", "ASM")
                            inferencing = False
                        else:
                            debug_print("Jump to other codes, start inference", "ASM")
                            inferencing = True
                    else:
                        debug_print("Found branch/condition instruction, but cannot find address information", "ASM")
                        inferencing = True
                    # if not before_instr == "tst":
                before_instr = instr
                for patterns in targetRegister:
                    for pattern in targetRegister[patterns]:
                        debug_print(f"Processing pattern: {pattern}", "ASM")
                        sp_search = re.search(sp_pattern, instrInfo)
                        if sp_search:
                            debug_print(f"Stack access detected: {stored_stack}", "ASM")
                            arg1 = instrInfo.split()[1]
                            if sp_search.group() in stored_stack and instr in ldInstr:
                                # stored_stack.remove(sp_search.group())
                                regpropa = extract_register_number(arg1)
                                if regpropa is None:
                                    continue
                                newpattern = fr"\b(x{regpropa}|w{regpropa})(?!\d)"
                                if newpattern not in targetRegister[patterns]:
                                    targetRegister[patterns].append(newpattern)
                                    debug_print(f"Updating target register patterns: {targetRegister}", "ASM")

                        if re.search(pattern, instrInfo):
                            arg1 = instrInfo.split()[1]
                            if re.search(pattern, arg1):
                                sp_search = re.search(sp_pattern, instrInfo)
                                if sp_search:
                                    if instr in stInstr:
                                        debug_print(f"Storing target pointer in stack: {sp_search.group()}", "ASM")
                                        stored_stack.append(sp_search.group())
                                else:
                                    while(1):
                                        if instr in stInstr or instr in branchInstr or instr:
                                            debug_print(f"Not updating target register patterns", "ASM")
                                            break
                                        if instr == "mov":
                                            arg2 = instrInfo.split()[2]
                                            found_pattern = False
                                            for other_pattern in targetRegister[patterns]:
                                                if re.search(other_pattern, arg2):
                                                    debug_print(f"Copying target address {arg2} to {arg1}", "ASM")
                                                    found_pattern = True
                                            if found_pattern:
                                                break
                                        if instr == "add" and pattern in offsetAddedRegister:
                                            addOffset = instrInfo.split('(')[1].split(')')[0]
                                            if offsetAddedRegister[pattern] == addOffset:
                                                break
                                            else:
                                                del offsetAddedRegister[pattern]
                                        debug_print(f"Removing pattern: {line.strip()} | {instrInfo}", "ASM")
                                        targetRegister[patterns].remove(pattern)
                                        break
                            elif instr in ldInstr:
                                if patterns not in get_havetoFind:
                                    continue
                                if re.search(pattern, arg1):
                                    debug_print("Unexpected instruction pattern in load operation", "WARNING")
                                if '#' in instrInfo:
                                    if (pattern in offsetAddedRegister):
                                        debug_print("Duplicate offset detected in load operation", "WARNING")
                                    offset = instrInfo.split('#')[1].split(']')[0]
                                    debug_print("Load field access operation detected", "ASM")
                                    if instr == "ldr":
                                        ldResult.append(
                                            [offset, "obj", inferencing, patterns])
                                    elif instr == "ldrb":
                                        ldResult.append(
                                            [offset, "bool", inferencing, patterns])
                                    else:
                                        # ldResult.append(
                                        #     [offset, "obj", inferencing, patterns])
                                        debug_print(f"Unsupported load instruction: {instr} in {line.strip()}", "SKIP")
                                        continue
                                    break
                                else:
                                    if re.search(pattern, arg1):
                                        continue
                                    if pattern in offsetAddedRegister:
                                        debug_print("Load field access operation with cached offset", "ASM")
                                        ldResult.append([offsetAddedRegister[pattern], "obj", inferencing, patterns])
                                    else:
                                        # access metadata of object
                                        continue
                            elif instr in stInstr:
                                if patterns not in set_havetoFind:
                                    continue
                                if re.search(pattern, arg1):
                                    debug_print("Unexpected instruction pattern in store operation", "WARNING")
                                if '#' in instrInfo:
                                    if (pattern in offsetAddedRegister):
                                        debug_print("Duplicate offset detected in store operation", "WARNING")
                                    debug_print("Store field access operation detected", "ASM")
                                    offset = instrInfo.split('#')[1].split(']')[0]
                                    if instr == "str":
                                        stResult.append(
                                            [offset, "obj", inferencing, patterns])
                                    elif instr == "strb":
                                        stResult.append(
                                            [offset, "bool", inferencing, patterns])
                                    else:
                                        # stResult.append(
                                        #     [offset, "obj", inferencing, patterns])
                                        debug_print(f"Unsupported store instruction: {instr} in {line.strip()}", "SKIP")
                                        continue
                                    break
                                else:
                                    if re.search(pattern, arg1):
                                        continue
                                    if pattern in offsetAddedRegister:
                                        debug_print("Store field access operation with cached offset", "ASM")
                                        stResult.append([offsetAddedRegister[pattern], "obj", inferencing, patterns])
                                    else:
                                        # access metadata of object
                                        continue
                            elif instr == "mov":
                                #  mov x23, x2
                                regpropa = extract_register_number(arg1)
                                if regpropa is None:
                                    continue
                                newpattern = fr"\b(x{regpropa}|w{regpropa})(?!\d)"
                                if newpattern in targetRegister[patterns]:
                                    continue
                                targetRegister[patterns].append(newpattern)
                                debug_print(f"Updating target register patterns: {targetRegister}", "ASM")
                                break
                            elif instr == "add":
                                if re.search(pattern, arg1):
                                    debug_print("Unexpected instruction pattern in add operation", "WARNING")
                                regpropa = extract_register_number(arg1)
                                if regpropa is None:
                                    continue
                                newpattern = fr"\b(x{regpropa}|w{regpropa})(?!\d)"
                                if ('(') not in instrInfo:
                                    debug_print("Unexpected instruction pattern in add operation", "SKIP")
                                    continue
                                addOffset = instrInfo.split('(')[1].split(')')[0]
                                if newpattern in targetRegister[patterns]:
                                    offsetAddedRegister[newpattern] = addOffset
                                    continue
                                targetRegister[patterns].append(newpattern)
                                offsetAddedRegister[newpattern] = addOffset
                                debug_print(f"Updating offset pattern: {targetRegister}, offset: {addOffset}", "ASM")
                            else:
                                pass
                            pass

def exclusive_assignment_inference():
    """
    Apply exclusive assignment inference to determine field offsets.
    
    This function uses the principle that each field must have a unique offset.
    It performs set difference operations to exclude other fields' candidates,
    leaving only the unique candidate for each field.
    
    Algorithm:
    1. For each field with multiple candidates, start with its candidate set
    2. Subtract all other fields' candidate sets from the current field's set
    3. If only one candidate remains, assign it directly to the field
    4. If successful assignments are made, recursively apply other inference methods
    
    Returns:
        None (modifies global MemoryLayout)
    """
    exclusive_assignments = 0
    debug_print("Starting exclusive_assignment_inference()", "INFERENCE")
    for target in MemoryLayout:
        for field in MemoryLayout[target]:
            if type(MemoryLayout[target][field]) != str:
                debug_print(f"Processing field {field} for exclusive assignment inference", "INFERENCE")
                debug_print(f"Original candidates: {MemoryLayout[target][field]}", "INFERENCE")
                final_set = MemoryLayout[target][field][0]
                for rec_field in MemoryLayout[target]:
                    if type(MemoryLayout[target][rec_field]) != str:
                        if field == rec_field:
                            continue
                        before_set = final_set.copy()
                        final_set = final_set - MemoryLayout[target][rec_field][0]
                        debug_print(f"Subtracting {MemoryLayout[target][rec_field][0]} from {field}: {before_set} -> {final_set}", "INFERENCE")
                if len(final_set) == 1:
                    exclusive_assignments += 1
                    debug_print(f"Exclusive assignment successful for {field}: {final_set}", "INFERENCE")
                    MemoryLayout[target][field] = [final_set]
                else:
                    debug_print(f"Exclusive assignment failed for {field}: remaining {len(final_set)} candidates", "INFERENCE")
    if exclusive_assignments >= 1:
        debug_print(f"Exclusive assignment applied to {exclusive_assignments} fields", "INFERENCE")
        print("start exclusive assignment")
        print(MemoryLayout)
        recursively_check()
        reduce_inference()
    else:
        debug_print("No exclusive assignment applied", "INFERENCE")

# Intersection-based inference functionality
intersection_failed = set()

def reduce_inference():
    """
    Apply intersection-based inference to reduce field offset candidates.
    
    This function uses set intersection to find common candidates across multiple
    inference attempts for the same field. It reduces the candidate set by
    keeping only the elements that appear in all candidate sets.
    
    Algorithm:
    1. For each field with multiple candidate sets, compute their intersection
    2. If intersection is empty, mark field as failed and skip
    3. If intersection reduces the candidate set, update the field's candidates
    4. If any reduction occurred, recursively apply other inference methods
    
    The intersection operation helps eliminate inconsistent candidates that
    cannot be valid offsets for a field based on multiple analysis results.
    
    Returns:
        None (modifies global MemoryLayout)
    """
    reduced = False
    debug_print("Starting reduce_inference()", "INFERENCE")
    for target in MemoryLayout:
        for field in MemoryLayout[target]:
            if type(MemoryLayout[target][field]) != str and field not in intersection_failed:
                debug_print(f"Processing field {field} with {len(MemoryLayout[target][field])} candidates", "INFERENCE")
                debug_print(f"Original candidates: {MemoryLayout[target][field]}", "INFERENCE")
                final_set = set()
                for candidate in range(len(MemoryLayout[target][field])):
                    tmp_set = MemoryLayout[target][field][candidate]
                    if candidate == 0:
                        final_set = tmp_set
                    else:
                        before_size = len(final_set)
                        final_set = final_set & tmp_set
                        after_size = len(final_set)
                        if before_size != after_size:
                            reduced = True
                            debug_print(f"Intersection reduced candidates for {field}: {before_size} -> {after_size}", "INFERENCE")
                if len(final_set) == 0:
                    # Intersection operation failed - no common candidates
                    debug_print(f"Intersection-based inference failed for field {field}", "WARNING")
                    intersection_failed.add(field)
                    continue
                debug_print(f"Final intersection result for {field}: {final_set}", "INFERENCE")
                MemoryLayout[target][field] = [final_set]
    if reduced:
        debug_print("Reduction occurred, calling recursively_check() and reduce_inference() again", "INFERENCE")
        print(MemoryLayout)
        recursively_check()
        reduce_inference()
    else:
        debug_print("No reduction occurred in reduce_inference()", "INFERENCE")

directMap  = set()
def recursively_check():
    """
    Apply recursive elimination to resolve field offset candidates.
    
    This function implements a two-pass algorithm to determine field offsets:
    
    1. Direct Mapping Pass: Prioritize single-element candidate sets for immediate assignment
    2. Elimination Pass: Remove known direct mappings from multi-element candidates
    
    The function ensures deterministic behavior by processing single-element candidates
    first, which helps establish a foundation for further inference steps.
    
    Algorithm:
    - First pass: Find fields with single-element candidate sets and assign them directly
    - Second pass: Remove already-assigned values from remaining multi-element candidates
    - Recursively call itself when new direct mappings are found
    
    Returns:
        None (modifies global MemoryLayout and directMap)
    """
    global directMap
    debug_print("Starting recursively_check()", "INFERENCE")
    debug_print(f"Current MemoryLayout: {MemoryLayout}", "INFERENCE")
    
    # First pass: prioritize single-element candidates for direct mapping
    for target in MemoryLayout:
        for field in MemoryLayout[target]:
            if type(MemoryLayout[target][field]) == str:
                directMap.add(MemoryLayout[target][field])
            else:
                # Look for single-element candidates first 
                for candidate in range(len(MemoryLayout[target][field])):
                    if len(MemoryLayout[target][field][candidate]) == 1:
                        for valuess in MemoryLayout[target][field][candidate]:
                            if valuess not in directMap:
                                MemoryLayout[target][field] = MemoryLayout[target][field][candidate].pop()
                                directMap.add(MemoryLayout[target][field])
                                recursively_check()
                                return
                            else:
                                MemoryLayout[target][field][candidate].pop()
                            break
    
    # Second pass: remove known direct mappings from multi-element candidates
    for target in MemoryLayout:
        for field in MemoryLayout[target]:
            if type(MemoryLayout[target][field]) != str:
                for candidate in range(len(MemoryLayout[target][field])):
                    # Sort directMap for deterministic processing
                    sorted_directMap = sorted(directMap)
                    for direct in sorted_directMap:
                        if direct in MemoryLayout[target][field][candidate]:
                            MemoryLayout[target][field][candidate].remove(direct)
                            if len(MemoryLayout[target][field][candidate]) == 1:
                                MemoryLayout[target][field] = MemoryLayout[target][field][candidate].pop()
                                directMap.add(MemoryLayout[target][field])
                                recursively_check()
                                return

OffsetFile = "input/targetOffset.txt"

# This section is now handled by the main() function

def main():
    """
    Main function for Android object field offset recovery tool.
    
    Usage:
        python3 OffsetAnalysis_minimal.py [target_class] [output_file]
        
    Arguments:
        target_class: Target Android class name (default: android.content.Intent)
        output_file:  Output file name (default: {target_class}_output.txt)
        
    Examples:
        python3 OffsetAnalysis_minimal.py
        python3 OffsetAnalysis_minimal.py android.app.Activity
        python3 OffsetAnalysis_minimal.py android.content.Intent intent_offsets.txt
    """
    import sys
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Android Object Field Offset Recovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s android.app.Activity
  %(prog)s android.content.Intent intent_offsets.txt

This tool analyzes Android framework OAT files to recover field offsets
for specified Android classes using static analysis techniques.
        """
    )
    
    parser.add_argument('target_class', 
                       nargs='?', 
                       default='android.content.Intent',
                       help='Target Android class name (default: android.content.Intent)')
    
    parser.add_argument('output_file', 
                       nargs='?', 
                       default=None,
                       help='Output file name (default: {target_class}_output.txt)')
    
    parser.add_argument('--debug', 
                       action='store_true',
                       help='Enable debug output')
    
    args = parser.parse_args()
    
    # Set debug mode
    global DEBUG_ENABLED
    DEBUG_ENABLED = args.debug
    
    # Generate output filename if not provided
    if args.output_file is None:
        # Convert class name to safe filename
        safe_class_name = args.target_class.replace('.', '_').replace('$', '_')
        args.output_file = f"{safe_class_name}_output.txt"
    
    # Configuration
    targetDir = "input/"
    # targetFile = "boot-framework-oat-reduced.log"
    targetFile = "boot-framework-oat.log"
    if not os.path.exists(target_dir + target_file):
        reduced_files = [
            target_dir + "boot-framework-app.log",
            target_dir + "boot-framework-app1.log",
            target_dir + "boot-framework-content.log",
        ]

        with open(target_dir + target_file, "w") as out:
            for f in reduced_files:
                with open(f, "r") as rf:
                    out.write(rf.read())


    print(f"Target Class: {args.target_class}")
    print(f"Output File: {args.output_file}")
    print(f"Debug Mode: {'Enabled' if DEBUG_ENABLED else 'Disabled'}")
    print("-" * 50)
    
    try:
        # Initialize class information
        OffsetFile = "input/targetOffset.txt"
        findClassInfo(args.target_class, OffsetFile)
        if currentClassName == "":
            print(f"Error: Target class '{args.target_class}' not found in offset file")
            print("Please ensure the target class exists in 'input/targetOffset.txt'")
            sys.exit(1)
        
        # Analyze the target class
        FindingLayoutInfo(targetDir + targetFile, args.target_class)
        
        # Count initial analysis results (before inference)
        none_cnt = 0
        initial_direct_cnt = 0  # Fields resolved through direct mapping initially
        initial_unresolved_cnt = 0  # Fields with multiple candidates initially
        
        for target in MemoryLayout:
            for field in MemoryLayout[target]:
                if type(MemoryLayout[target][field]) == str:
                    if MemoryLayout[target][field] == "NONE":
                        none_cnt += 1
                    else:
                        initial_direct_cnt += 1
                else:
                    initial_unresolved_cnt += 1
        
        debug_print("Initial memory layout", "RESULT")
        debug_print(str(MemoryLayout), "RESULT")
        
        # Apply inference algorithms
        recursively_check()
        recursively_check()
        debug_print("After recursive check", "RESULT")
        debug_print(str(MemoryLayout), "RESULT")
        
        reduce_inference()
        debug_print("After reduce inference", "RESULT")
        debug_print(str(MemoryLayout), "RESULT")
        
        exclusive_assignment_inference()
        # recursively_check()
        debug_print("After exclusive assignment inference", "RESULT")
        debug_print(str(MemoryLayout), "RESULT")
        
        # Count final analysis results (after inference)
        final_resolved_cnt = 0
        final_unresolved_cnt = 0
        final_none_cnt = 0
        
        for target in MemoryLayout:
            for field in MemoryLayout[target]:
                if type(MemoryLayout[target][field]) == str:
                    if MemoryLayout[target][field] == "NONE":
                        final_none_cnt += 1
                    else:
                        final_resolved_cnt += 1
                else:
                    final_unresolved_cnt += 1
        
        # Calculate statistics
        case1_cnt = initial_direct_cnt  # Direct mapping count (unchanged)
        case2_cnt = final_resolved_cnt - case1_cnt  # Inference mapping count
        none_cnt = final_none_cnt  # Update unresolved count
        
        # Write results to output file
        with open(args.output_file, 'w') as f:
            f.write(f"# Java Object Field Offset Recovery Results\n")
            f.write(f"# Target Class: {args.target_class}\n")
            f.write(f"# \n")
            f.write(f"# Statistics:\n")
            f.write(f"# - Direct Mapping : {case1_cnt}\n")
            f.write(f"# - Inference Mapping: {case2_cnt}\n")
            f.write(f"# - Candidate Generation: {initial_unresolved_cnt - case2_cnt}\n")
            f.write(f"# - Not used field: {none_cnt}\n")
            f.write(f"# \n")
            f.write(f"# Results:\n")
            f.write(str(MemoryLayout) + '\n')
        
        # Print final results
        print("\nAnalysis completed successfully!")
        print(f"Results written to: {args.output_file}")
        print(f"Statistics: Direct Mapping: {case1_cnt} resolved, Inference Mapping: {case2_cnt}, Candidate Generation: {initial_unresolved_cnt - case2_cnt}, Not used field: {none_cnt}")
        
        # Print final results to console
        print("\nFinal Results:")
        print(str(MemoryLayout))
        
    except FileNotFoundError as e:
        print(f"Error: Required input file not found: {e}")
        print("Please ensure 'input/boot-framework-oat.log' exists.")
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}")
        if DEBUG_ENABLED:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
