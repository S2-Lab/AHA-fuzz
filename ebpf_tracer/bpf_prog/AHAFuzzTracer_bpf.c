/**
 * AHAFuzz eBPF Tracer
 * 
 * This eBPF C program runs in the kernel and defines various tracepoints (uprobes)
 * and perf buffers to collect data from user-space Android processes. It filters
 * events by TARGET_UID and extracts relevant information like thread ID, addresses,
 * method indices, and string arguments. It also includes logic for modifying
 * scheduling times.
 * 
 * Author: AHAFuzz Team
 * License: See LICENSE file
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/ptrace.h>

// Runtime configuration (replaced by AHAFuzz.py)
#define MAX_STR_LEN set:MAX_STR_LEN
#define MAX_STR_COUNT set:MAX_STR_COUNT

// Note: AOT Hooking uses 32bit addresses, Interpreter (.so) Hooking uses 64bit

// =============================================================================
// Register Receiver Tracing
// =============================================================================

struct data_RR {
    u32 tid;
    char strs[MAX_STR_COUNT][MAX_STR_LEN];
    int total_len;
    int bit_lens[MAX_STR_COUNT];
    int broadcastreceiver;

} __attribute__((packed));

BPF_PERF_OUTPUT(registerReceiverTrace);
int registerReceiverTracer(struct pt_regs *ctx) { // trace_registerReceiverInternal
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    u32 mAction;
    u32 ArrayList;
    u32 string_addr;
    struct data_RR data = {};
    
   data.tid =  bpf_get_current_pid_tgid();
   void *brodcast_obj = PT_REGS_PARM3(ctx);
   bpf_probe_read(&data.broadcastreceiver, sizeof(data.broadcastreceiver), brodcast_obj + 2 * 8);
   data.broadcastreceiver = data.broadcastreceiver;// ^ PT_REGS_PARM3(ctx);

    void *str_obj = (void *) PT_REGS_PARM5(ctx);
    bpf_probe_read(&mAction, sizeof(mAction), str_obj + 2 * 4); // intent_filter *mAction
    bpf_probe_read(&data.total_len, sizeof(data.total_len), mAction + 2 * 4); // Array length
    bpf_probe_read(&ArrayList, sizeof(mAction), mAction + 3 * 4); // goto data.ArrayList
    
    int i = 0;
    for (i = 0; i< MAX_STR_COUNT; i++) {
        bpf_probe_read(&string_addr, sizeof(ArrayList), ArrayList + 3 * 4 + i * 4); // goto data.ArrayList
        string_addr += 8;
        bpf_probe_read(&data.bit_lens[i], sizeof(data.bit_lens[i]), string_addr);
        bpf_probe_read(&data.strs[i], MAX_STR_LEN, string_addr + 8);

        if (data.total_len -1 == i) {
            break;
        }
    }
    registerReceiverTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


/// unregisterReiver Tracing //

struct data_uRR {
    u32 tid;
    int broadcastreceiver;

} __attribute__((packed));

BPF_PERF_OUTPUT(unregisterReceiverTrace);
int unregisterReceiverTracer(struct pt_regs *ctx) { // trace_registerReceiverInternal
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
    struct data_uRR data = {};
    
    data.tid =  bpf_get_current_pid_tgid();
    void *brodcast_obj = PT_REGS_PARM3(ctx);
    bpf_probe_read(&data.broadcastreceiver, sizeof(data.broadcastreceiver), brodcast_obj + 2 * 8);
    data.broadcastreceiver = data.broadcastreceiver;// ^ PT_REGS_PARM3(ctx);
    unregisterReceiverTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/////////////////////////////////////////////////////////////////////////
// Manifest intent Monitoring
/////////////////////////////////////////////////////////////////////////

// Manifest intent Monitoring : Get intent action value
// android.content.BroadcastReceiver android.app.AppComponentFactory.instantiateReceiver(java.lang.ClassLoader, java.lang.String, android.content.Intent)
// android.app.Service android.app.AppComponentFactory.instantiateService(java.lang.ClassLoader, java.lang.String, android.content.Intent)

struct data_MIT {
    char strs[MAX_STR_LEN];
    int bit_lens;
} __attribute__((packed));

BPF_PERF_OUTPUT(ManifestReceiverTrace);
int ManifestReceiverTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_MIT data = {};
    int intent_addr;

    void *str_obj = (void *) PT_REGS_PARM5(ctx); // android.content.Intent
    
    bpf_probe_read(&intent_addr, sizeof(intent_addr), str_obj + 2 * 4); // intent addr
                
    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), intent_addr + 2 * 4); // Array length
    bpf_probe_read(&data.strs, MAX_STR_LEN, intent_addr + 4 * 4);
        
    ManifestReceiverTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
struct data_tmp {
    char strs[MAX_STR_LEN];
    int bit_lens;
} __attribute__((packed));

BPF_PERF_OUTPUT(prepareToEnterProcessTrace);
int prepareToEnterProcessTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_tmp data = {};
    int intent_addr;

    void *str_obj = (void *) PT_REGS_PARM2(ctx); // android.content.Intent

    bpf_probe_read(&intent_addr, sizeof(intent_addr), str_obj + 2 * 4); // intent addr

    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), intent_addr + 2 * 4); // Array length
    bpf_probe_read(&data.strs, MAX_STR_LEN, intent_addr + 4 * 4);

    prepareToEnterProcessTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

struct data_ser {
    char strs[MAX_STR_LEN];
    int bit_lens;
} __attribute__((packed));

BPF_PERF_OUTPUT(startServiceTrace);
int startServiceTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_ser data = {};
    int intent_addr;

    void *str_obj = (void *) PT_REGS_PARM3(ctx); // android.content.Intent

    bpf_probe_read(&intent_addr, sizeof(intent_addr), str_obj + 2 * 4); // intent addr

    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), intent_addr + 2 * 4); // Array length
    bpf_probe_read(&data.strs, MAX_STR_LEN, intent_addr + 4 * 4);

    startServiceTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
struct data_HSA {
    char strs[MAX_STR_LEN];
    int bit_lens;
} __attribute__((packed));

BPF_PERF_OUTPUT(handleServiceArgsTrace);
int handleServiceArgsTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_HSA data = {};
    int intent;
    int intent_addr;

    void* handleServiceArgs = (void *) PT_REGS_PARM3(ctx); // handleServiceArgs

    bpf_probe_read(&intent, sizeof(intent), handleServiceArgs + 2 * 4); // android.content.Intent
    bpf_probe_read(&intent_addr, sizeof(intent_addr), intent + 2 * 4); // intent action addr

    if (intent_addr != 0) {
        bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), intent_addr + 2 * 4); // Array length
        bpf_probe_read(&data.strs, MAX_STR_LEN, intent_addr + 4 * 4);

        handleServiceArgsTrace.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}


struct data_HR {
    char strs[MAX_STR_LEN];
    int bit_lens;
} __attribute__((packed));

BPF_PERF_OUTPUT(handleReceiverTrace);
int handleReceiverTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_HR data = {};
    int intent;
    int intent_action;

    void *ReceiverData = (void *) PT_REGS_PARM3(ctx); // ReceiverData

    bpf_probe_read(&intent, sizeof(intent), ReceiverData + 13 * 4); // android.content.Intent
    bpf_probe_read(&intent_action, sizeof(intent_action), intent + 2 * 4); // intent action addr

    if (intent_action != 0) {
        bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), intent_action + 2 * 4); // Array length
        bpf_probe_read(&data.strs, MAX_STR_LEN, intent_action + 4 * 4);

        handleReceiverTrace.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}


struct data_RMI {
    u32 addr;
    u32 tid;
};

BPF_PERF_OUTPUT(ManifestRetTrace);
int ManifestRetTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
    struct data_RMI data = {};
    data.tid =  bpf_get_current_pid_tgid();
    data.addr = PT_REGS_IP(ctx);
        
    ManifestRetTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/////////////////////////////////////////////////////////////////////////
// Method Coverage Feedback 
/////////////////////////////////////////////////////////////////////////

// performReceive Tracing : Get intent action value
// android.app.LoadedApk$ReceiverDispatcher.performReceive(android.content.Intent, int, java.lang.String, android.os.Bundle, boolean, boolean, int)
struct data_IT {
    char strs[MAX_STR_LEN];
    int bit_lens;
} __attribute__((packed));

BPF_PERF_OUTPUT(IntentTrace);
int IntentTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_IT data = {};
    int intent_addr;

    void *str_obj = (void *) PT_REGS_PARM3(ctx); // android.content.Intent
    
    bpf_probe_read(&intent_addr, sizeof(intent_addr), str_obj + 2 * 4); // intent addr
                
    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), intent_addr + 2 * 4); // Array length
    bpf_probe_read(&data.strs, MAX_STR_LEN, intent_addr + 4 * 4);
        
    IntentTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


// enqueueMessageAddr, dispatchMessageAddr Tracing
// boolean android.os.MessageQueue.enqueueMessage(android.os.Message, long)
// void android.os.Handler.dispatchMessage(android.os.Message)
struct data_MT {
    u64 ts;
    u32 tid;
    u32 addr;
    u32 runnable;
} __attribute__((packed));

BPF_PERF_OUTPUT(MessageTrace);
int MessageTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_MT data = {};
    data.tid =  bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns() / 1000;
    data.addr = PT_REGS_IP(ctx);            
                
    void *str_obj = (void *) PT_REGS_PARM3(ctx); // android.os.Message
    bpf_probe_read(&data.runnable, sizeof(data.runnable), str_obj + 2 * 4); // runnable
        
    MessageTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


/////////////////////////////////////////////////////////////////////////
// Basic Feedback (Just know about that method was called or not)
/////////////////////////////////////////////////////////////////////////

// Type A : Tracing more less Call information(Address)
struct data_SAT {
    u32 tid;
    u32 addr;
} __attribute__((packed));

BPF_PERF_OUTPUT(FinTrace);
int FinTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_SAT data = {};
    data.tid =  bpf_get_current_pid_tgid();
    data.addr = PT_REGS_IP(ctx);
        
    FinTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Type A' : Tracing more less Call information(Address) (64)
struct data_SAT1 {
    u32 tid;
    u64 addr;
};

BPF_PERF_OUTPUT(FinTrace1);
int FinTracer1(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_SAT1 data = {};
    data.tid =  bpf_get_current_pid_tgid();
    data.addr = PT_REGS_IP(ctx);
        
    FinTrace1.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


// Type B : Tracing only Call information(Time, Address)
struct data_AT {
    u32 tid;
    u32 addr;
} __attribute__((packed));

BPF_PERF_OUTPUT(AOTTrace);
int AOTTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_AT data = {};
    data.tid =  bpf_get_current_pid_tgid();
    data.addr = PT_REGS_IP(ctx);
        
    AOTTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Type c : Tracing only Address : Using SharedPreferences Scheduling
struct data_SPS {
    u32 addr;
} __attribute__((packed));

BPF_PERF_OUTPUT(SharedPreferenceTrace);
int SharedPreferenceTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_SPS data = {};
    data.addr = PT_REGS_IP(ctx);
        
    SharedPreferenceTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


/////////////////////////////////////////////////////////////////////////
// Interpreter Hooking
/////////////////////////////////////////////////////////////////////////

// Tracing MTERP
// 1. MTERP : Machine TERP
    // NterpGetMethod(Thread*, ArtMethod* ..)
    // NterpGetStaticField(Thread*, ArtMethod* ..)
    // NterpGetInstanceFieldOffset(Thread*, ArtMethod* ..)
    // NterpGetClassOrAllocateObject(Thread*, ArtMethod* ..)
    // NterpLoadObject(Thread*, ArtMethod* ..)
struct data_MTERP {
    u32 tid;
    u64 method_head;
    u32 method_idx;
};
BPF_PERF_OUTPUT(MterpInterpreterTrace);
        
int MterpInterpreterTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_MTERP data = {};
    data.tid =  bpf_get_current_pid_tgid();
    void *str_obj = (void *) PT_REGS_PARM2(ctx); // ArtMethod*
    if (str_obj < 0xfffffff){
        return 0;
    }
    // bpf_probe_read(&data.method_head, sizeof(data.method_head), str_obj); // method_head
    data.method_head = (void *) PT_REGS_PARM2(ctx); // ArtMethod*
    // if(data.method_head < STARTING_ADDRESS ) return 0;
    bpf_probe_read(&data.method_idx, sizeof(data.method_idx), str_obj + 8); // method_idx = method_head + 8
    if (data.method_idx == 0 || data.method_idx > 0xffff){
        return 0;
    }

    MterpInterpreterTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


// 2. No MTERP - ArtMethod::Invoke()
//     art_quick_invoke_stub(ArtMethod* ..)
//     art_quick_invoke_static_stub(ArtMethod* ..)
struct data_Inv {
    u32 tid;
    u64 method_head;
    u32 method_idx;
};
BPF_PERF_OUTPUT(InvokeInterpreterTrace);
        
int InvokeInterpreterTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_Inv data = {};
    data.tid =  bpf_get_current_pid_tgid();
    void *str_obj = (void *) PT_REGS_PARM1(ctx); // ArtMethod*
    // bpf_probe_read(&data.method_head, sizeof(data.method_head), str_obj); // method_head
    data.method_head = (void *) PT_REGS_PARM1(ctx); // ArtMethod*
    // if(data.method_head < STARTING_ADDRESS) return 0;
    bpf_probe_read(&data.method_idx, sizeof(data.method_idx), str_obj + 8); // method_idx = method_head + 8

    InvokeInterpreterTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 3. No MTERP - Interpreter::Execute()
    // ExecuteSwitchImplAsm(&ctx...)
        // .self
        // .accessor
        // shadow_frame
            // link
            // method_
struct data_EXE {
    u32 tid;
    u64 method_head;
    u32 method_idx;
};
BPF_PERF_OUTPUT(ExecuteInterpreterTrace);
        
int ExecuteInterpreterTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_EXE data = {};
    data.tid =  bpf_get_current_pid_tgid();
    void *str_obj = (void *) PT_REGS_PARM1(ctx); // ctx
    // ctx {
    //  .self : +0x0
    //  .accessor : +0x8
    //  .shadow_frame : +0x10
    //  ...
    // }
    u64 shadow_frame;
    bpf_probe_read(&shadow_frame, sizeof(shadow_frame), str_obj + 2 * sizeof(shadow_frame)); // shadow frame = ctx + 16

    // shadow_frame {
    //  link : +0x0
    //  method_ : +0x8
    // }
    u64 method_;
    bpf_probe_read(&method_, sizeof(method_), shadow_frame + 1 * sizeof(method_));

    // bpf_probe_read(&data.method_head, sizeof(data.method_head), method_); // method_head
    bpf_probe_read(&data.method_head, sizeof(data.method_head), shadow_frame + 1 * sizeof(data.method_head));
    // if(data.method_head < STARTING_ADDRESS) return 0;
    bpf_probe_read(&data.method_idx, sizeof(data.method_idx), method_ + 8); // method_idx = method_head + 8

    ExecuteInterpreterTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/////////////////////////////////////////////////////////////////////////
// Custom Intent Feedback tracing
/////////////////////////////////////////////////////////////////////////
struct data_CT {
    u32 tid;
    u32 addr;
    char strs[MAX_STR_LEN];
    int bit_lens;
} __attribute__((packed));

BPF_PERF_OUTPUT(CustomTrace);
int CustomTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_CT data = {};

    void *str_obj = (void *) PT_REGS_PARM3(ctx);
    data.tid =  bpf_get_current_pid_tgid();
    data.addr = PT_REGS_IP(ctx);
    
    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), str_obj + 2 * 4); // Array length
    if(data.bit_lens == 0) {
        return 0;
    }
    bpf_probe_read(&data.strs, MAX_STR_LEN, str_obj + 4 * 4);
        
    CustomTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


// Trace this & 1st argument's string

struct data_CTD {
    u32 tid;
    u32 addr;
    char strs1[MAX_STR_LEN];
    char strs2[MAX_STR_LEN];
    int bit_lens1;
    int bit_lens2;
} __attribute__((packed));

BPF_PERF_OUTPUT(CustomDDTrace);
int CustomDDTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_CTD data = {};

    void *str_obj1 = (void *) PT_REGS_PARM2(ctx);
    void *str_obj2 = (void *) PT_REGS_PARM3(ctx);
    data.tid =  bpf_get_current_pid_tgid();
    data.addr = PT_REGS_IP(ctx);
    
    bpf_probe_read(&data.bit_lens1, sizeof(data.bit_lens1), str_obj1 + 2 * 4); // Array length
    bpf_probe_read(&data.bit_lens2, sizeof(data.bit_lens2), str_obj2 + 2 * 4); // Array length
    if(data.bit_lens1 == 0 && data.bit_lens2 == 0) {
        return 0;
    }
    bpf_probe_read(&data.strs1, MAX_STR_LEN, str_obj1 + 4 * 4);
    bpf_probe_read(&data.strs2, MAX_STR_LEN, str_obj2 + 4 * 4);
        
    CustomDDTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/////////////////////////////////////////////////////////////////////////
// Scheduling Tracing & Overwrite the value with BPF_write
// Return How much
/////////////////////////////////////////////////////////////////////////

// Store latest scheduling event clock into counter variable
BPF_HASH(counter, u64, u64, 8192);

// JobScheduler - setMinimumLatency
// Hook this method in return statement 
// android.app.job.JobInfo$Builder android.app.job.JobInfo$Builder.setMinimumLatency(long)
struct data_JST {
    u64 latency;
};
BPF_PERF_OUTPUT(JobSchedulerTrace);

int JobSchedulerTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
    struct data_JST data = {};
    void *str_obj = (void *) PT_REGS_PARM2(ctx);

    // bpf_probe_read(&data.latency, sizeof(data.latency), str_obj + sizeof(data.latency));
    data.latency = PT_REGS_PARM3(ctx);

    u64 target_latency = TARGET_LATENCY;
    if (data.latency > target_latency) {
        unsigned long long clock = ((unsigned long long) bpf_ktime_get_boot_ns() / 1000000) & 0xffffffff;
        u64 key = 0, init_val = 1;
        u64 *val = counter.lookup_or_try_init(&key, &init_val);
        if (val) {
            unsigned long long Scheduling_diff = clock + TARGET_LATENCY - ((unsigned long long) (*val));
            if (Scheduling_diff >= TARGET_LATENCY && (clock >> 32 <= 0)) {
                (*val) = clock + TARGET_LATENCY;
                bpf_probe_write_user(str_obj + 8 * 8, &target_latency, 8);
                JobSchedulerTrace.perf_submit(ctx, &data, sizeof(data));
            } else { // Scheduling after the 10 second is needed
                (*val) = clock + TARGET_LATENCY + Scheduling_diff;
                target_latency += Scheduling_diff;
                bpf_probe_write_user(str_obj + 8 * 8, &target_latency, 8);
            }
            // data.latency = Scheduling_diff;
        }
        // bpf_probe_write_user(str_obj + 8 * 8, &target_latency, 8);
        // JobSchedulerTrace.perf_submit(ctx, &data, sizeof(data));
    }
        
    return 0;
}




struct data_pDT {
    u32 tid;
    u32 addr;
    unsigned long long diff;
    u64 clock;
};
BPF_PERF_OUTPUT(postDelayedTrace);

// postDelyed() -> ... -> android.os.MessageQueue.enqueueMessage(android.os.Message, long)
// long => current time + scheduling time
int postDelayedTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_pDT data = {};
    data.tid =  bpf_get_current_pid_tgid();
    data.addr = PT_REGS_IP(ctx);
    data.clock = ((unsigned long long) bpf_ktime_get_boot_ns() / 1000000) & 0xffffffff;
    u64 target_time = (unsigned long long) PT_REGS_PARM4(ctx) & 0xffffffff;
    if(target_time <= data.clock){
        return 0;
    }

    unsigned long long diff = abs(target_time - data.clock);
    data.diff = diff;

    if (diff > TARGET_LATENCY && diff < 108000000) { // 108000000 = 30hour
            u64 key = 0, init_val = 1;
            u64 *val = counter.lookup_or_try_init(&key, &init_val);
            if (val) {
                unsigned long long Scheduling_diff = data.clock + TARGET_LATENCY - ((unsigned long long) (*val));
                if (Scheduling_diff >= TARGET_LATENCY && (data.clock >> 32 <= 0)) {
                    data.clock += TARGET_LATENCY;
                    (*val) = data.clock;
                    bpf_probe_write_user(ctx->regs[23] + 32, &data.clock, 8);
                    postDelayedTrace.perf_submit(ctx, &data, sizeof(data));
                } else { // Scheduling after the 10 second is needed
                    data.clock = (*val) + TARGET_LATENCY;
                    (*val) = data.clock;
                    bpf_probe_write_user(ctx->regs[23] + 32, &data.clock, 8);
                    // postDelayedTrace.perf_submit(ctx, &data, sizeof(data));
                }
                // data.diff = (*val);
            }

        // void *str_obj = (void *) PT_REGS_PARM3(ctx);
        // u32 message;
        // bpf_probe_read(&message, sizeof(message), str_obj + 2 * sizeof(message));
        // u32 obj;
        // bpf_probe_read(&obj, sizeof(obj), message);
        // if(0x10000000 < obj && obj < 0x60000000){
        //     unsigned int key = 0;
        //     long *value;
        //     value = example_map.lookup(&key);
        //     if (value) {
        //         (*value)+= 10;
        //     }
        //     // data.clock += TARGET_LATENCY + value;
        //     // data.diff += value;
        //     data.clock += TARGET_LATENCY;
        //     bpf_probe_write_user(ctx->regs[23] + 32, &data.clock, 8);
        //     postDelayedTrace.perf_submit(ctx, &data, sizeof(data));
        // }


    }

    return 0;
}



struct data_AMT {
    u32 tid;
    u32 addr;
    u64 clock;
    u64 interval;
};
BPF_PERF_OUTPUT(AlarmManagerTrace);

int AlarmManagerTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_AMT data = {};
    data.tid =  bpf_get_current_pid_tgid();
    data.addr = PT_REGS_IP(ctx);
    data.clock = PT_REGS_PARM4(ctx);
    data.interval = PT_REGS_PARM6(ctx);

    AlarmManagerTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


struct data_SST {
    u32 addr;
    char strs[256];
    int bit_lens;
};

BPF_PERF_OUTPUT(SourceStrTrace);
int SourceStrTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_SST data = {};
    data.addr = PT_REGS_IP(ctx);

    void *str_obj = (void *) PT_REGS_PARM1(ctx);
    int len;
    
    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), str_obj + 2 * 4); // length
    if(data.bit_lens == 0) {
        return 0;
    }
    bpf_probe_read(&data.strs, 256, str_obj + 4 * 4);
        
    SourceStrTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


struct data_SPT {
    u32 addr;
    u64 priv;
};

BPF_PERF_OUTPUT(SourcePrivTrace);
int SourcePrivTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_SPT data = {};
    data.addr = PT_REGS_IP(ctx);
    data.priv = PT_REGS_PARM1(ctx);

    SourcePrivTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


struct data_S1T {
    u32 addr;
    char strs[256];
    int bit_lens;
    u64 priv;
};

BPF_PERF_OUTPUT(Sink1stTrace);
int Sink1stTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_S1T data = {};
    data.addr = PT_REGS_IP(ctx);

    void *str_obj = (void *) PT_REGS_PARM3(ctx);
    int len;
    
    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), str_obj + 2 * 4); // length
    if((data.bit_lens <= 0) || (data.bit_lens >= 1000)) {
        data.bit_lens == 0;
        data.priv = PT_REGS_PARM3(ctx);
    } else{
        bpf_probe_read(&data.strs, 256, str_obj + 4 * 4);
    }
    Sink1stTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

struct data_S2T {
    u32 addr;
    char strs[256];
    int bit_lens;
    u64 priv;
};

BPF_PERF_OUTPUT(Sink2ndTrace);
int Sink2ndTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_S2T data = {};
    data.addr = PT_REGS_IP(ctx);

    void *str_obj = (void *) PT_REGS_PARM4(ctx);
    int len;
    
    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), str_obj + 2 * 4); // length
    if((data.bit_lens <= 0) || (data.bit_lens >= 1000)) {
        data.bit_lens == 0;
        data.priv = PT_REGS_PARM3(ctx);
    } else{
        bpf_probe_read(&data.strs, 256, str_obj + 4 * 4);
    }
    Sink2ndTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
struct data_S3T {
    u32 addr;
    char strs[256];
    int bit_lens;
    u64 priv;
};

BPF_PERF_OUTPUT(Sink3rdTrace);
int Sink3rdTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_S3T data = {};
    data.addr = PT_REGS_IP(ctx);

    void *str_obj = (void *) PT_REGS_PARM5(ctx);
    int len;
    
    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), str_obj + 2 * 4); // length
    if((data.bit_lens <= 0) || (data.bit_lens >= 1000)) {
        data.bit_lens == 0;
        data.priv = PT_REGS_PARM3(ctx);
    } else{
        bpf_probe_read(&data.strs, 256, str_obj + 4 * 4);
    }
    Sink3rdTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


struct data_PIT {
    u32 addr;
    char strs[256];
    int bit_lens;
    u64 priv;
};

BPF_PERF_OUTPUT(PropagateInputTrace);
int PropagateInputTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_PIT data = {};
    data.addr = PT_REGS_IP(ctx);

    void *str_obj = (void *) PT_REGS_PARM3(ctx);
    int len;
    
    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), str_obj + 2 * 4); // length
    if((data.bit_lens <= 0) || (data.bit_lens >= 1000)) {
        data.bit_lens == 0;
        data.priv = PT_REGS_PARM3(ctx);
    } else{
        bpf_probe_read(&data.strs, 256, str_obj + 4 * 4);
    }
    PropagateInputTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

struct data_POT {
    u32 addr;
    char strs[256];
    int bit_lens;
    u64 priv;
};

BPF_PERF_OUTPUT(PropagateOutputTrace);
int PropagateOutputTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }
        
    struct data_POT data = {};
    data.addr = PT_REGS_IP(ctx);

    void *str_obj = (void *) PT_REGS_PARM3(ctx);
    int len;
    
    bpf_probe_read(&data.bit_lens, sizeof(data.bit_lens), str_obj + 2 * 4); // length
    if((data.bit_lens <= 0) || (data.bit_lens >= 1000)) {
        data.bit_lens == 0;
        data.priv = PT_REGS_PARM1(ctx);
    } else{
        bpf_probe_read(&data.strs, 256, str_obj + 4 * 4);
    }
    PropagateOutputTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}









struct data_DEBUG {
    u64 lr;
    u64 addr;
};
BPF_PERF_OUTPUT(DebuggingTrace);

int DebuggingTracer(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid != TARGET_UID) {
        return 0;
    }

    struct data_DEBUG data = {};
    data.lr = ctx->regs[30];  // LR is x30
    data.addr = PT_REGS_IP(ctx);

    DebuggingTrace.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


        // data.str_param1 = PT_REGS_PARM1(ctx);
        // data.str_param2 = PT_REGS_PARM2(ctx);
        // data.str_param3 = PT_REGS_PARM3(ctx);
        // data.str_param4 = PT_REGS_PARM4(ctx)& 0xffffffff;
        // // data.str_param5 = PT_REGS_PARM5(ctx);
        // data.str_param5 = bpf_ktime_get_boot_ns();
        // data.str_param6 =((unsigned long long) bpf_ktime_get_boot_ns() / 1000000)& 0xffffffff;
        // data.str_param7 =((unsigned long long) bpf_ktime_get_boot_ns() / 1000000)& 0xffffffff;
        // bpf_probe_write_user(str_obj + 8 * sizeof(data.str1), &data.str_param6, 8);
        // // bpf_probe_read(&data.str_param7, sizeof(data.str1), str_obj + 8 * sizeof(data.str1));
        // data.str_param8 = 100000;
        // // if(data.addr == 0x7266100c){
        // //     for (i = 0; i < 16; i++) {
        // //         bpf_probe_read(&data.str1 + i, sizeof(data.str1), (void *) ctx->regs[23] + i * sizeof(data.str1));
        // //     }
        // // }
        // if((data.addr == 0x72661010) && (abs((unsigned long long) data.str_param4) - abs((unsigned long long) data.str_param7) > 10000 )){
        //     // data.str_param7 += abs((unsigned long long) data.str_param4) - abs((unsigned long long) data.str_param7);
        //     data.str_param7 += 10000;
            // bpf_probe_write_user(ctx->regs[23] + 32, &data.str_param7, 8);
        //     events.perf_submit(ctx, &data, sizeof(data));
        // }else{
        //     data.str_param7 = 0;
        // }
        // events.perf_submit(ctx, &data, sizeof(data));




    // int trace_ArtMethod_invoke(struct pt_regs *ctx) {
    //     u32 uid = bpf_get_current_uid_gid();
    //     if (uid != 10168) {
    //         return 0;
    //     }

    //     struct data_t data = {};
    //     data.pid = bpf_get_current_pid_tgid();
    //     u64 pid_tgid = bpf_get_current_pid_tgid();
    //     data.pid = pid_tgid & 0xFFFFFFFF;
    //     data.tid = pid_tgid >> 32;
    //     data.ts = bpf_ktime_get_ns() / 1000;
    //     data.addr = PT_REGS_IP(ctx);
    //     bpf_get_current_comm(&data.comm, sizeof(data.comm));

    //     // Tracing art::jit::Jit::MethodEntered(art::Thread*, art::ArtMethod*)
    //     void *str_obj = (void *) PT_REGS_PARM2(ctx);
    //     // bpf_probe_read(&data.str1, sizeof(data.str1), str_obj);
    //     // bpf_probe_read(&data.str2, sizeof(data.str1), data.str1 + 3 * 4);
    //     // bpf_probe_read(&data.str3, sizeof(data.str2), data.str2 + 3 * 4);
    //     int i = 0;
    //     for (i = 0; i < 16; i++) {
    //         // bpf_probe_read(&data.str2 + i, 4, data.str1 + i * 4);
    //         bpf_probe_read(&data.str1 + i, sizeof(data.str1), str_obj + i * sizeof(data.str1));
    //     }
    //     for (i = 16; i < 40; i++) {
    //         // bpf_probe_read(&data.str2 + i, 4, data.str1 + i * 4);
    //         bpf_probe_read(&data.str1 + i, sizeof(data.str1), data.str3 + (i-16) * sizeof(data.str1));
    //     }

    //     data.str_param1 = PT_REGS_PARM1(ctx);
    //     data.str_param2 = PT_REGS_PARM2(ctx);
    //     data.str_param3 = PT_REGS_PARM3(ctx);
    //     data.str_param4 = PT_REGS_PARM4(ctx);
    //     data.str_param5 = PT_REGS_PARM5(ctx);
    //     data.str_param6 = 1000;
    //     data.str_param7 = 0;
        // bpf_probe_write_user(str_obj + 8 * sizeof(data.str1), &data.str_param6, 8);
    //     // bpf_probe_read(&data.str_param7, sizeof(data.str1), str_obj + 8 * sizeof(data.str1));
    //     data.str_param8 = tmp();

    //     events.perf_submit(ctx, &data, sizeof(data));
    //     return 0;
    // }


























































































































































































































// ///////////////////////////////////////////////////////////////////
// //                   Anti analysis(NCScope)                      //
// ///////////////////////////////////////////////////////////////////

//     // strcmp //

// struct strcmp_param {
//     u64 ts;
//     char p0[128];
//     char p1[128];
// };
// BPF_HASH(strcmp_records, u64, struct strcmp_param, 8192);

// int strcmp_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }
    
//     struct strcmp_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
//         return 0;
//     if (record.p0[0] == '[' || record.p1[0] == '[') // filter
//         return 0;
//     if (record.p0[0] == '_' || record.p1[0] == '_') // filter
//         return 0;
//     if (record.p0[0] == '<' || record.p1[0] == '<') // filter
//         return 0;
//     if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
//         return 0;
//     // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
//     //     return 0;
//     // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
//     //     return 0;
    
//     if ((record.p0[0]=='g' && record.p0[1]=='l')
//      || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
//         return 0;
//     if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
//      || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
//         return 0;
//     if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
//      || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
//      || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
//      || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
//      || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
//         return 0;
//     if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
//      || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
//         return 0;
    
//     strcmp_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // strcasecmp //

// struct strcasecmp_param {
//     u64 ts;
//     char p0[128];
//     char p1[128];
// };
// BPF_HASH(strcasecmp_records, u64, struct strcasecmp_param, 8192);

// int strcasecmp_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }
    
//     struct strcasecmp_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
//         return 0;
//     if (record.p0[0] == '[' || record.p1[0] == '[') // filter
//         return 0;
//     if (record.p0[0] == '_' || record.p1[0] == '_') // filter
//         return 0;
//     if (record.p0[0] == '<' || record.p1[0] == '<') // filter
//         return 0;
//     if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
//         return 0;
//     // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
//     //     return 0;
//     // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
//     //     return 0;
    
//     if ((record.p0[0]=='g' && record.p0[1]=='l')
//      || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
//         return 0;
//     if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
//      || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
//         return 0;
//     if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
//      || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
//      || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
//      || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
//      || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
//         return 0;
//     if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
//      || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
//         return 0;
    
//     strcasecmp_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // strncmp //

// struct strncmp_param {
//     u64 ts;
//     char p0[128];
//     char p1[128];
// };
// BPF_HASH(strncmp_records, u64, struct strncmp_param, 8192);

// int strncmp_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct strncmp_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
//         return 0;
//     if (record.p0[0] == '[' || record.p1[0] == '[') // filter
//         return 0;
//     if (record.p0[0] == '_' || record.p1[0] == '_') // filter
//         return 0;
//     if (record.p0[0] == '<' || record.p1[0] == '<') // filter
//         return 0;
//     if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
//         return 0;
//     // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
//     //     return 0;
//     // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
//     //     return 0;
    
//     if ((record.p0[0]=='g' && record.p0[1]=='l')
//      || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
//         return 0;
//     if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
//      || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
//         return 0;
//     if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
//      || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
//      || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
//      || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
//      || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
//         return 0;
//     if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
//      || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
//         return 0;
    
//     strncmp_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // strncasecmp //

// struct strncasecmp_param {
//     u64 ts;
//     char p0[128];
//     char p1[128];
// };
// BPF_HASH(strncasecmp_records, u64, struct strncasecmp_param, 8192);

// int strncasecmp_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct strncasecmp_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
//         return 0;
//     if (record.p0[0] == '[' || record.p1[0] == '[') // filter
//         return 0;
//     if (record.p0[0] == '_' || record.p1[0] == '_') // filter
//         return 0;
//     if (record.p0[0] == '<' || record.p1[0] == '<') // filter
//         return 0;
//     if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
//         return 0;
//     // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
//     //     return 0;
//     // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
//     //     return 0;
    
//     if ((record.p0[0]=='g' && record.p0[1]=='l')
//      || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
//         return 0;
//     if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
//      || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
//         return 0;
//     if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
//      || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
//      || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
//      || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
//      || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
//         return 0;
//     if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
//      || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
//         return 0;
    
//     strncasecmp_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // strstr //

// struct strstr_param {
//     u64 ts;
//     char p0[128];
//     char p1[128];
// };
// BPF_HASH(strstr_records, u64, struct strstr_param, 8192);

// int strstr_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct strstr_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
//         return 0;
//     if (record.p0[0] == '[' || record.p1[0] == '[') // filter
//         return 0;
//     if (record.p0[0] == '_' || record.p1[0] == '_') // filter
//         return 0;
//     if (record.p0[0] == '<' || record.p1[0] == '<') // filter
//         return 0;
//     if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
//         return 0;
//     // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
//     //     return 0;
//     // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
//     //     return 0;
    
//     if ((record.p0[0]=='g' && record.p0[1]=='l')
//      || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
//         return 0;
//     if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
//      || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
//         return 0;
//     if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
//      || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
//      || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
//      || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
//         return 0;
//     if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
//      || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
//         return 0;
//     if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
//      || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
//         return 0;
    
//     strstr_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // open //

// struct open_param {
//     u64 ts;
//     char p0[256];
// };
// BPF_HASH(open_records, u64, struct open_param, 8192);

// int open_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct open_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     open_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // openat //

// struct openat_param {
//     u64 ts;
//     char p1[256];
// };
// BPF_HASH(openat_records, u64, struct openat_param, 8192);

// int openat_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM2(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct openat_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p1[0] == '\\0') // filter
//         return 0;
    
//     openat_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // fopen //

// struct fopen_param {
//     u64 ts;
//     char p0[256];
// };
// BPF_HASH(fopen_records, u64, struct fopen_param, 8192);

// int fopen_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct fopen_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     fopen_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // write //

// struct write_param {
//     u64 ts;
//     u32 p2;
// };
// BPF_HASH(write_records, u64, struct write_param, 8192);

// int write_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct write_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.p2 = PT_REGS_PARM3(ctx);
    
//     write_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // access //

// struct access_param {
//     u64 ts;
//     char p0[256];
// };
// BPF_HASH(access_records, u64, struct access_param, 8192);

// int access_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct access_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     access_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // stat //

// struct stat_param {
//     u64 ts;
//     char p0[256];
// };
// BPF_HASH(stat_records, u64, struct stat_param, 8192);

// int stat_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct stat_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     stat_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // __system_property_get //

// struct sys_property_get_param {
//     u64 ts;
//     char p0[256];
// };
// BPF_HASH(sys_property_get_records, u64, struct sys_property_get_param, 8192);

// int sys_property_get_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct sys_property_get_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     sys_property_get_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // popen //

// struct popen_param {
//     u64 ts;
//     char p0[256];
// };
// BPF_HASH(popen_records, u64, struct popen_param, 8192);

// int popen_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct popen_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     popen_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // execl //

// struct execl_param {
//     u64 ts;
//     char p0[64];
//     char p1[64];
//     char p2[64];
//     char p3[64];
// };
// BPF_HASH(execl_records, u64, struct execl_param, 8192);

// int execl_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct execl_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     record.p0[63] = 0;
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
//     record.p1[63] = 0;
//     bpf_probe_read(&record.p2, sizeof(record.p2), (void *) (PT_REGS_PARM3(ctx) & 0xFFFFFFFFFF));
//     record.p2[63] = 0;
//     bpf_probe_read(&record.p3, sizeof(record.p3), (void *) (PT_REGS_PARM4(ctx) & 0xFFFFFFFFFF));
//     record.p3[63] = 0;
    
//     // if (record.p0[0] == '/')
//     //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     execl_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // execle //

// struct execle_param {
//     u64 ts;
//     char p0[64];
//     char p1[64];
//     char p2[64];
//     char p3[64];
// };
// BPF_HASH(execle_records, u64, struct execle_param, 8192);

// int execle_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct execle_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     record.p0[63] = 0;
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
//     record.p1[63] = 0;
//     bpf_probe_read(&record.p2, sizeof(record.p2), (void *) (PT_REGS_PARM3(ctx) & 0xFFFFFFFFFF));
//     record.p2[63] = 0;
//     bpf_probe_read(&record.p3, sizeof(record.p3), (void *) (PT_REGS_PARM4(ctx) & 0xFFFFFFFFFF));
//     record.p3[63] = 0;
    
//     // if (record.p0[0] == '/')
//     //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     execle_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // execlp //

// struct execlp_param {
//     u64 ts;
//     char p0[64];
//     char p1[64];
//     char p2[64];
//     char p3[64];
// };
// BPF_HASH(execlp_records, u64, struct execlp_param, 8192);

// int execlp_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct execlp_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     record.p0[63] = 0;
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
//     record.p1[63] = 0;
//     bpf_probe_read(&record.p2, sizeof(record.p2), (void *) (PT_REGS_PARM3(ctx) & 0xFFFFFFFFFF));
//     record.p2[63] = 0;
//     bpf_probe_read(&record.p3, sizeof(record.p3), (void *) (PT_REGS_PARM4(ctx) & 0xFFFFFFFFFF));
//     record.p3[63] = 0;
    
//     // if (record.p0[0] == '/')
//     //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     execlp_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // execv //

// struct execv_param {
//     u64 ts;
//     char p0[64];
//     char p1[64];
//     char p2[64];
//     char p3[64];
// };
// BPF_HASH(execv_records, u64, struct execv_param, 8192);

// int execv_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct execv_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     record.p0[63] = 0;
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
//     record.p1[63] = 0;
//     bpf_probe_read(&record.p2, sizeof(record.p2), (void *) (PT_REGS_PARM3(ctx) & 0xFFFFFFFFFF));
//     record.p2[63] = 0;
//     bpf_probe_read(&record.p3, sizeof(record.p3), (void *) (PT_REGS_PARM4(ctx) & 0xFFFFFFFFFF));
//     record.p3[63] = 0;
    
//     // if (record.p0[0] == '/')
//     //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     execv_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // execvp //

// struct execvp_param {
//     u64 ts;
//     char p0[64];
//     char p1[64];
//     char p2[64];
//     char p3[64];
// };
// BPF_HASH(execvp_records, u64, struct execvp_param, 8192);

// int execvp_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct execvp_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     record.p0[63] = 0;
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
//     record.p1[63] = 0;
//     bpf_probe_read(&record.p2, sizeof(record.p2), (void *) (PT_REGS_PARM3(ctx) & 0xFFFFFFFFFF));
//     record.p2[63] = 0;
//     bpf_probe_read(&record.p3, sizeof(record.p3), (void *) (PT_REGS_PARM4(ctx) & 0xFFFFFFFFFF));
//     record.p3[63] = 0;
    
//     // if (record.p0[0] == '/')
//     //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     execvp_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // execvpe //

// struct execvpe_param {
//     u64 ts;
//     char p0[64];
//     char p1[64];
//     char p2[64];
//     char p3[64];
// };
// BPF_HASH(execvpe_records, u64, struct execvpe_param, 8192);

// int execvpe_hook(struct pt_regs *ctx) {
//     if (!PT_REGS_PARM1(ctx))
//         return 0;
        
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct execvpe_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
//     record.p0[63] = 0;
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
//     record.p1[63] = 0;
//     bpf_probe_read(&record.p2, sizeof(record.p2), (void *) (PT_REGS_PARM3(ctx) & 0xFFFFFFFFFF));
//     record.p2[63] = 0;
//     bpf_probe_read(&record.p3, sizeof(record.p3), (void *) (PT_REGS_PARM4(ctx) & 0xFFFFFFFFFF));
//     record.p3[63] = 0;
    
//     // if (record.p0[0] == '/')
//     //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     execvpe_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // mmap //

// struct mmap_enter_param {
//     u64 ts;
//     u64 p0;
//     u64 p1;
//     u32 p2;
// };
// BPF_HASH(mmap_enter_records, u64, struct mmap_enter_param, 8192);

// int mmap_enter_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct mmap_enter_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.p0 = PT_REGS_PARM1(ctx);
//     record.p1 = PT_REGS_PARM2(ctx);
//     record.p2 = PT_REGS_PARM3(ctx);
    
//     mmap_enter_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// struct mmap_return_param {
//     u64 ts;
//     u64 ret;
// };
// BPF_HASH(mmap_return_records, u64, struct mmap_return_param, 8192);

// int mmap_return_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct mmap_return_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.ret = PT_REGS_RC(ctx);
    
//     mmap_return_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // mprotect //

// struct mprotect_param {
//     u64 ts;
//     u64 p0;
//     u64 p1;
//     u32 p2;
// };
// BPF_HASH(mprotect_records, u64, struct mprotect_param, 8192);

// int mprotect_hook(struct pt_regs *ctx) {
//     if ((PT_REGS_PARM3(ctx) & 0x4) != 0x4)
//         return 0;
//     if (PT_REGS_PARM1(ctx) <= 0xffffffff)
//         return 0;

//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct mprotect_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.p0 = PT_REGS_PARM1(ctx);
//     record.p1 = PT_REGS_PARM2(ctx);
//     record.p2 = PT_REGS_PARM3(ctx);
    
//     mprotect_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // memcpy //
// struct memcpy_param {
//     u64 ts;
//     u64 p0;
//     u64 p1;
//     u64 p2;
// };
// BPF_HASH(memcpy_records, u64, struct memcpy_param, 8192);

// int memcpy_hook(struct pt_regs *ctx) {
//     if (PT_REGS_PARM3(ctx) == 0)
//         return 0; // ignore PROT_NONE

//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct memcpy_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.p0 = PT_REGS_PARM1(ctx);
//     record.p1 = PT_REGS_PARM2(ctx);
//     record.p2 = PT_REGS_PARM3(ctx);
    
//     memcpy_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // time //

// struct time_param {
//     u64 ts;
// };
// BPF_HASH(time_records, u64, struct time_param, 8192);

// int time_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct time_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     time_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // gettimeofday //

// struct gettimeofday_param {
//     u64 ts;
// };
// BPF_HASH(gettimeofday_records, u64, struct gettimeofday_param, 8192);

// int gettimeofday_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct gettimeofday_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     gettimeofday_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // do_dlopen (linker) //
// // struct dlopen_param {
// //     u64 ts;
// //     u32 pid;
// //     u32 tid;
// //     char p0[128];
// // };
// // BPF_HASH(dlopen_records, u64, struct dlopen_param, 8192);

// // int dlopen_hook(struct pt_regs *ctx) {
// //     if (!PT_REGS_PARM1(ctx))
// //         return 0;
        
// //     u32 uid = bpf_get_current_uid_gid();
// //     if (uid != TARGET_UID) {
// //         return 0;
// //     }
// //     u32 pid = bpf_get_current_pid_tgid() >> 32;
// //     u32 tid = bpf_get_current_pid_tgid();

// //     struct dlopen_param record = {};
    
// //     record.ts = bpf_ktime_get_ns();
// //
// //
// //     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
// //     dlopen_records.lookup_or_init(&record.ts, &record);
    
// //     return 0;
// // };

// // JavaVMExt::LoadNativeLibrary (libart) //

// struct dlopen_param {
//     u64 ts;
//     char p0[256];
// };
// BPF_HASH(dlopen_records, u64, struct dlopen_param, 8192);

// int dlopen_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct dlopen_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     u64 path_ptr;
//     // bpf_probe_read(&path_ptr, sizeof(path_ptr), (void *) ((PT_REGS_PARM3(ctx) & 0xFFFFFFFFFF) + 0x2));
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM3(ctx) + 0x1));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     dlopen_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // JavaVMExt::LoadNativeLibrary (libart) //

// struct dlopen_ret_param {
//     u64 ts;
// };
// BPF_HASH(dlopen_ret_records, u64, struct dlopen_ret_param, 8192);

// int dlopen_ret_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct dlopen_ret_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     dlopen_ret_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // art::DexFileLoader::OpenCommon //
// /*
// struct open_common_param {
//     u64 ts;
//     u64 p0;
// };
// BPF_HASH(open_common_records, u64, struct open_common_param, 8192);

// int open_common_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct open_common_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.p0 = PT_REGS_PARM1(ctx);
    
//     open_common_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };
// */

// // CompactDexFile::CompactDexFile //
// /*
// struct compact_init_param {
//     u64 ts;
//     u64 p0;
//     u64 p1;
//     u64 p2;
//     u64 p3;
// };
// BPF_HASH(compact_init_records, u64, struct compact_init_param, 8192);

// int compact_init_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct compact_init_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.p0 = PT_REGS_PARM1(ctx);
//     record.p1 = PT_REGS_PARM2(ctx);
//     record.p2 = PT_REGS_PARM3(ctx);
//     record.p3 = PT_REGS_PARM4(ctx);
    
//     compact_init_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };
// */

// // DexFile::DexFile //

// struct dexfile_init_param {
//     u64 ts;
//     u64 p1; // const uint8_t* base
//     // u32 p2; // size_t size
//     // u64 p5; 
//     char p5[256]; // const std::string&
// };
// BPF_HASH(dexfile_init_records, u64, struct dexfile_init_param, 8192);

// int dexfile_init_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct dexfile_init_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.p1 = PT_REGS_PARM2(ctx);
//     // record.p2 = PT_REGS_PARM3(ctx);
//     // bpf_probe_read(&record.p5, sizeof(record.p5), (void *)(PT_REGS_PARM6(ctx) + 0x10));
//     u64 location_ptr;
//     bpf_probe_read(&location_ptr, sizeof(location_ptr), (void *) ((PT_REGS_PARM6(ctx) + 0x10) & 0xFFFFFFFFFF));
//     bpf_probe_read(&record.p5, sizeof(record.p5), (void *)location_ptr);
    
//     if (record.p5[0] == '\\0') // filter
//         return 0;
    
//     dexfile_init_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // JniMethodStart //
// /*
// struct jni_start_param {
//     u64 ts;
// };
// BPF_HASH(jni_start_records, u64, struct jni_start_param, 8192);

// // -->>

// struct reg {
//     u64 ts;
//     u64 x0;
//     u64 x1;
//     u64 x2;
//     u64 x3;
//     u64 x4;
//     u64 x5;
//     u64 x6;
//     u64 x7;
//     u64 x8;
//     u64 x9;
//     u64 x10;
//     u64 x11;
//     u64 x12;
//     u64 x13;
//     u64 x14;
//     u64 x15;
//     u64 x16;
//     u64 x17;
//     u64 x18;
//     u64 x19;
//     u64 x20;
//     u64 x21;
//     u64 x22;
//     u64 x23;
//     u64 x24;
//     u64 x25;
//     u64 x26;
//     u64 x27;
//     u64 x28;
//     u64 x29;
//     u64 x30;
//     u64 sp;
//     u64 pc;
//     u64 pstate;
// };

// struct libc_rx {
//     char buf[0xd2000];
// };
// struct libc_r {
//     char buf[0x6000];
// };
// struct libc_rw {
//     char buf[0x2000];
// };

// BPF_ARRAY(reg_records, struct reg, 1);
// BPF_ARRAY(libc_r_records, struct libc_r, 1);
// BPF_ARRAY(libc_rw_records, struct libc_rw, 1);
// BPF_ARRAY(libc_rx_records, struct libc_rx, 1);

// // <<--

// int jni_start_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jni_start_param param = {};
    
//     param.ts = bpf_ktime_get_ns();
//     param.pid = pid;
//     param.tid = tid;
    
//     jni_start_records.lookup_or_init(&param.ts, &param);
    
//     // -->>
    
//     int index = 0;
    
//     struct reg *record = reg_records.lookup(&index);
//     if (record == NULL)
//         return 0;
//     record->ts = bpf_ktime_get_ns();
//     record->pid = pid;
//     record->tid = tid;
//     record->x0 = ((struct user_pt_regs*) ctx)->regs[0];
//     record->x1 = ((struct user_pt_regs*) ctx)->regs[1];
//     record->x2 = ((struct user_pt_regs*) ctx)->regs[2];
//     record->x3 = ((struct user_pt_regs*) ctx)->regs[3];
//     record->x4 = ((struct user_pt_regs*) ctx)->regs[4];
//     record->x5 = ((struct user_pt_regs*) ctx)->regs[5];
//     record->x6 = ((struct user_pt_regs*) ctx)->regs[6];
//     record->x7 = ((struct user_pt_regs*) ctx)->regs[7];
//     record->x8 = ((struct user_pt_regs*) ctx)->regs[8];
//     record->x9 = ((struct user_pt_regs*) ctx)->regs[9];
//     record->x10 = ((struct user_pt_regs*) ctx)->regs[10];
//     record->x11 = ((struct user_pt_regs*) ctx)->regs[11];
//     record->x12 = ((struct user_pt_regs*) ctx)->regs[12];
//     record->x13 = ((struct user_pt_regs*) ctx)->regs[13];
//     record->x14 = ((struct user_pt_regs*) ctx)->regs[14];
//     record->x15 = ((struct user_pt_regs*) ctx)->regs[15];
//     record->x16 = ((struct user_pt_regs*) ctx)->regs[16];
//     record->x17 = ((struct user_pt_regs*) ctx)->regs[17];
//     record->x18 = ((struct user_pt_regs*) ctx)->regs[18];
//     record->x19 = ((struct user_pt_regs*) ctx)->regs[19];
//     record->x20 = ((struct user_pt_regs*) ctx)->regs[20];
//     record->x21 = ((struct user_pt_regs*) ctx)->regs[21];
//     record->x22 = ((struct user_pt_regs*) ctx)->regs[22];
//     record->x23 = ((struct user_pt_regs*) ctx)->regs[23];
//     record->x24 = ((struct user_pt_regs*) ctx)->regs[24];
//     record->x25 = ((struct user_pt_regs*) ctx)->regs[25];
//     record->x26 = ((struct user_pt_regs*) ctx)->regs[26];
//     record->x27 = ((struct user_pt_regs*) ctx)->regs[27];
//     record->x28 = ((struct user_pt_regs*) ctx)->regs[28];
//     record->x29 = ((struct user_pt_regs*) ctx)->regs[29];
//     record->x30 = ((struct user_pt_regs*) ctx)->regs[30];
//     record->sp = ((struct user_pt_regs*) ctx)->sp;
//     record->pc = ((struct user_pt_regs*) ctx)->pc;
//     record->pstate = ((struct user_pt_regs*) ctx)->pstate;
    
//     struct libc_rx *data_libc_rx = libc_rx_records.lookup(&index);
//     if (data_libc_rx == NULL)
//         return 0;
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
//     bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    
//     struct libc_r *data_libc_r = libc_r_records.lookup(&index);
//     if (data_libc_r == NULL)
//         return 0;
//     bpf_probe_read(&(data_libc_r->buf), sizeof(data_libc_r->buf), (void *)0x7dde36a000);
    
//     struct libc_r *data_libc_rw = libc_r_records.lookup(&index);
//     if (data_libc_rw == NULL)
//         return 0;
//     bpf_probe_read(&(data_libc_rw->buf), sizeof(data_libc_rw->buf), (void *)0x7dde370000);
    
//     // <<--
    
//     return 0;
// };
// */

// // JniMethodFastStart //
// /*
// struct jni_faststart_param {
//     u64 ts;
// };
// BPF_HASH(jni_faststart_records, u64, struct jni_faststart_param, 8192);

// int jni_faststart_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jni_faststart_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     jni_faststart_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };
// */

// // JniMethodEnd //
// /*
// struct jni_end_param {
//     u64 ts;
// };
// BPF_HASH(jni_end_records, u64, struct jni_end_param, 8192);

// int jni_end_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jni_end_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     jni_end_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };
// */

// // JniMethodFastEnd //
// /*
// struct jni_fastend_param {
//     u64 ts;
// };
// BPF_HASH(jni_fastend_records, u64, struct jni_fastend_param, 8192);

// int jni_fastend_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jni_fastend_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     jni_fastend_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };
// */

// // JniMethodEndSynchronized //
// /*
// struct jni_endsynchronized_param {
//     u64 ts;
// };
// BPF_HASH(jni_endsynchronized_records, u64, struct jni_endsynchronized_param, 8192);

// int jni_endsynchronized_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jni_endsynchronized_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     jni_endsynchronized_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };
// */

// // JniMethodEndWithReferenceHandleResult //
// /*
// struct jni_endreference_param {
//     u64 ts;
// };
// BPF_HASH(jni_endreference_records, u64, struct jni_endreference_param, 8192);

// int jni_endreference_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jni_endreference_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     jni_endreference_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };
// */

// // polyu_JNI_start //

// struct jni_start_param {
//     u64 ts;
//     char p0[256];
// };
// BPF_HASH(jni_start_records, u64, struct jni_start_param, 8192);

// int jni_start_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jni_start_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     jni_start_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // polyu_JNI_end //

// struct jni_end_param {
//     u64 ts;
//     char p0[128];
// };
// BPF_HASH(jni_end_records, u64, struct jni_end_param, 8192);

// int jni_end_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jni_end_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     jni_end_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // VMDebug_isDebuggerConnected //

// struct jdwp_debug_param {
//     u64 ts;
// };
// BPF_HASH(jdwp_debug_records, u64, struct jdwp_debug_param, 8192);

// int jdwp_debug_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jdwp_debug_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     jdwp_debug_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // JNI_NewString //

// struct new_string_param {
//     u64 ts;
//     char p1[128];
// };
// BPF_HASH(new_string_records, u64, struct new_string_param, 8192);

// int new_string_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct new_string_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p1[0] == '\\0') // filter
//         return 0;
//     if (record.p1[1] == '\\0') // filter
//         return 0;
    
//     new_string_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // JNI_NewStringUTF //

// struct new_stringutf_param {
//     u64 ts;
//     char p1[128];
// };
// BPF_HASH(new_stringutf_records, u64, struct new_stringutf_param, 8192);

// int new_stringutf_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct new_stringutf_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p1[0] == '\\0') // filter
//         return 0;
//     if (record.p1[1] == '\\0') // filter
//         return 0;
    
//     new_stringutf_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // JNI_FindClass //

// struct find_class_param {
//     u64 ts;
//     char p1[128];
// };
// BPF_HASH(find_class_records, u64, struct find_class_param, 8192);

// int find_class_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct find_class_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p1, sizeof(record.p1), (void *) (PT_REGS_PARM2(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p1[0] == '\\0') // filter
//         return 0;
    
//     find_class_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // JNI_FindMethodId //

// struct find_methodid_param {
//     u64 ts;
//     char p2[128];
// };
// BPF_HASH(find_methodid_records, u64, struct find_methodid_param, 8192);

// int find_methodid_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct find_methodid_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p2, sizeof(record.p2), (void *) (PT_REGS_PARM3(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p2[0] == '\\0') // filter
//         return 0;
    
//     find_methodid_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // JNI_FindFieldId //

// struct find_fieldid_param {
//     u64 ts;
//     char p2[128];
// };
// BPF_HASH(find_fieldid_records, u64, struct find_fieldid_param, 8192);

// int find_fieldid_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct find_fieldid_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p2, sizeof(record.p2), (void *) (PT_REGS_PARM3(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p2[0] == '\\0') // filter
//         return 0;
    
//     find_fieldid_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // InvokeWithArgArray //

// struct jni_invoke_param {
//     u64 ts;
//     char p0[128];
// };
// BPF_HASH(jni_invoke_records, u64, struct jni_invoke_param, 8192);

// int jni_invoke_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct jni_invoke_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     bpf_probe_read(&record.p0, sizeof(record.p0), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     if (record.p0[0] == '\\0') // filter
//         return 0;
    
//     jni_invoke_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // connect IPv4 //

// struct connect4_param {
//     u64 ts;
//     u32 daddr;
//     u16 dport;
// };
// BPF_HASH(connect4_records, u64, struct connect4_param, 8192);

// int connect4_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }
    
//     struct connect4_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
    
//     u64 struct_ptr = PT_REGS_PARM2(ctx);
//     bpf_probe_read(&record.dport, sizeof(record.dport), (void *) ((struct_ptr + 0x2) & 0xFFFFFFFFFF));
//     bpf_probe_read(&record.daddr, sizeof(record.daddr), (void *) ((struct_ptr + 0x4) & 0xFFFFFFFFFF));
	
// 	connect4_records.lookup_or_init(&record.ts, &record);
	
// 	return 0;
// };

// // cacheflush //
// /*
// struct cacheflush_param {
//     u64 ts;
//     // u32 no;
//     u64 saddr;
//     u64 eaddr;
// };
// BPF_HASH(cacheflush_records, u64, struct cacheflush_param, 8192);

// int cacheflush_hook(struct pt_regs *ctx) {
//     // if (pid < 1000)
//         // return 0;
//     u32 tid = bpf_get_current_pid_tgid();
//     if (tid != pid)
//         return 0;
    
//     struct cacheflush_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
// 	record.pid = pid;
    
//     struct pt_regs regs = {};
//     bpf_probe_read(&regs, sizeof(regs), (void *) (PT_REGS_PARM1(ctx) & 0xFFFFFFFFFF));
    
//     // record.no = regs.regs[7];
    
//     if (regs.regs[7] != 0x0f0002)
//         return 0;
    
//     record.saddr = regs.regs[0];
//     record.eaddr = regs.regs[1];
    
//     cacheflush_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };
// */

// // fork //

// struct fork_return_param {
//     u64 ts;
//     u32 ret;
// };
// BPF_HASH(fork_return_records, u64, struct fork_return_param, 8192);

// int fork_return_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct fork_return_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.ret = PT_REGS_RC(ctx);
    
//     fork_return_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // sys_brk //

// struct sys_brk_param {
//     u64 ts;
//     u64 p0;
// };
// BPF_HASH(sys_brk_records, u64, struct sys_brk_param, 8192);

// int sys_brk_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct sys_brk_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.p0 = PT_REGS_PARM1(ctx);
    
//     sys_brk_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// // sys_mmap //

// struct sys_mmap_enter_param {
//     u64 ts;
//     u64 p0;
//     u64 p1;
//     u32 p2;
// };
// BPF_HASH(sys_mmap_enter_records, u64, struct sys_mmap_enter_param, 8192);

// int sys_mmap_enter_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct sys_mmap_enter_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.p0 = PT_REGS_PARM1(ctx);
//     record.p1 = PT_REGS_PARM2(ctx);
//     record.p2 = PT_REGS_PARM3(ctx);
    
//     sys_mmap_enter_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };

// struct sys_mmap_return_param {
//     u64 ts;
//     u64 ret;
// };
// BPF_HASH(sys_mmap_return_records, u64, struct sys_mmap_return_param, 8192);

// int sys_mmap_return_hook(struct pt_regs *ctx) {
//     u32 uid = bpf_get_current_uid_gid();
//     if (uid != TARGET_UID) {
//         return 0;
//     }

//     struct sys_mmap_return_param record = {};
    
//     record.ts = bpf_ktime_get_ns();
//     record.ret = PT_REGS_RC(ctx);
    
//     sys_mmap_return_records.lookup_or_init(&record.ts, &record);
    
//     return 0;
// };