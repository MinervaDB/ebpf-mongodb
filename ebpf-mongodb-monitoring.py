#!/usr/bin/env python3
"""
MongoDB eBPF Monitoring Solution

This script deploys eBPF programs to monitor MongoDB performance at the kernel level,
collecting metrics about I/O operations, network activity, CPU usage, and memory utilization.
"""

import argparse
import os
import signal
import sys
import time
from datetime import datetime

from bcc import BPF, PerfType, PerfSWConfig
import pymongo
import json
import psutil
import pandas as pd
import matplotlib.pyplot as plt
from prometheus_client import start_http_server, Gauge, Counter, Histogram

# eBPF C program for MongoDB monitoring
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <net/sock.h>

// Data structures for storing MongoDB metrics
struct mongodb_query_event_t {
    u64 timestamp;
    u64 duration_ns;
    u32 pid;
    u32 collection_len;
    char collection[64];
    u32 operation;  // 0: find, 1: insert, 2: update, 3: delete, 4: aggregate, 5: other
    u64 docs_examined;
    u64 docs_returned;
};

struct mongodb_io_event_t {
    u64 timestamp;
    u32 pid;
    u64 bytes;
    char operation;  // 'r' for read, 'w' for write
};

struct mongodb_net_event_t {
    u64 timestamp;
    u32 pid;
    u32 dport;
    u64 bytes;
    char direction;  // 'i' for ingress, 'e' for egress
};

// BPF maps to share data with user space
BPF_PERF_OUTPUT(mongodb_query_events);
BPF_PERF_OUTPUT(mongodb_io_events);
BPF_PERF_OUTPUT(mongodb_net_events);
BPF_HASH(start_query, u32, u64);

// MongoDB WiredTiger storage engine file operations tracking
int trace_wiredtiger_read_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Filter for MongoDB processes only
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        start_query.update(&pid, &ts);
    }
    
    return 0;
}

int trace_wiredtiger_read_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp = start_query.lookup(&pid);
    
    if (tsp != 0) {
        struct mongodb_io_event_t event = {};
        event.timestamp = bpf_ktime_get_ns();
        event.pid = pid;
        event.bytes = PT_REGS_RC(ctx);
        event.operation = 'r';
        
        mongodb_io_events.perf_submit(ctx, &event, sizeof(event));
        start_query.delete(&pid);
    }
    
    return 0;
}

int trace_wiredtiger_write_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        start_query.update(&pid, &ts);
    }
    
    return 0;
}

int trace_wiredtiger_write_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp = start_query.lookup(&pid);
    
    if (tsp != 0) {
        struct mongodb_io_event_t event = {};
        event.timestamp = bpf_ktime_get_ns();
        event.pid = pid;
        event.bytes = PT_REGS_RC(ctx);
        event.operation = 'w';
        
        mongodb_io_events.perf_submit(ctx, &event, sizeof(event));
        start_query.delete(&pid);
    }
    
    return 0;
}

// Network traffic monitoring
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (pid_is_mongodb(pid)) {
        struct mongodb_net_event_t event = {};
        u16 dport = 0;
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        
        event.timestamp = bpf_ktime_get_ns();
        event.pid = pid;
        event.dport = ntohs(dport);
        event.bytes = size;
        event.direction = 'e';  // egress
        
        mongodb_net_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

int trace_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        start_query.update(&pid, &ts);
    }
    
    return 0;
}

int trace_tcp_recvmsg_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp = start_query.lookup(&pid);
    
    if (tsp != 0) {
        struct mongodb_net_event_t event = {};
        ssize_t size = PT_REGS_RC(ctx);
        
        if (size > 0) {
            event.timestamp = bpf_ktime_get_ns();
            event.pid = pid;
            event.bytes = size;
            event.direction = 'i';  // ingress
            
            mongodb_net_events.perf_submit(ctx, &event, sizeof(event));
        }
        
        start_query.delete(&pid);
    }
    
    return 0;
}

// MongoDB query monitoring using USDT probes (if available) or function entry/return probes
int mongodb_query_start(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    start_query.update(&pid, &ts);
    return 0;
}

int mongodb_query_end(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp = start_query.lookup(&pid);
    
    if (tsp != 0) {
        struct mongodb_query_event_t event = {};
        u64 duration = bpf_ktime_get_ns() - *tsp;
        
        event.timestamp = *tsp;
        event.duration_ns = duration;
        event.pid = pid;
        
        // This part would need to be customized based on how you're extracting collection names
        // and query types from MongoDB's execution
        
        mongodb_query_events.perf_submit(ctx, &event, sizeof(event));
        start_query.delete(&pid);
    }
    
    return 0;
}

// Helper function to check if a process is MongoDB
static inline bool pid_is_mongodb(u32 pid) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Check if process name contains "mongod"
    char mongod[7] = "mongod";
    for (int i = 0; i < TASK_COMM_LEN - 6; i++) {
        bool match = true;
        for (int j = 0; j < 6; j++) {
            if (comm[i+j] != mongod[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    
    return false;
}
"""

class MongoDBEBPFMonitor:
    def __init__(self, mongo_uri="mongodb://localhost:27017", output_dir="./mongodb_metrics"):
        self.mongo_uri = mongo_uri
        self.output_dir = output_dir
        self.mongo_client = None
        self.bpf = None
        self.running = False
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize Prometheus metrics
        self.prom_metrics = {
            'query_duration': Histogram('mongodb_query_duration_seconds', 'Duration of MongoDB queries', 
                                        ['collection', 'operation']),
            'io_bytes': Counter('mongodb_io_bytes_total', 'Total bytes read/written by MongoDB', 
                               ['operation']),
            'net_bytes': Counter('mongodb_net_bytes_total', 'Total network bytes transferred by MongoDB', 
                                ['direction']),
            'docs_examined': Counter('mongodb_docs_examined_total', 'Total documents examined by MongoDB queries', 
                                    ['collection']),
            'docs_returned': Counter('mongodb_docs_returned_total', 'Total documents returned by MongoDB queries', 
                                    ['collection']),
            'collection_ops': Counter('mongodb_collection_operations_total', 
                                     'Total operations by collection', 
                                     ['collection', 'operation']),
            'locks': Gauge('mongodb_locks', 'MongoDB lock information', 
                          ['database', 'type']),
            'connections': Gauge('mongodb_connections', 'MongoDB connection information', 
                                ['state']),
            'memory_usage': Gauge('mongodb_memory_bytes', 'MongoDB memory usage', 
                                 ['type']),
            'cpu_usage': Gauge('mongodb_cpu_percent', 'MongoDB CPU usage percentage')
        }
        
        # Start Prometheus HTTP server
        start_http_server(8000)
        
    def connect_to_mongodb(self):
        try:
            self.mongo_client = pymongo.MongoClient(self.mongo_uri)
            print(f"Connected to MongoDB: {self.mongo_uri}")
            return True
        except Exception as e:
            print(f"Error connecting to MongoDB: {e}")
            return False

    def load_ebpf_program(self):
        try:
            self.bpf = BPF(text=bpf_program)
            
            # Attach kprobes for file operations
            self.bpf.attach_kprobe(event="__wt_read", fn_name="trace_wiredtiger_read_entry")
            self.bpf.attach_kretprobe(event="__wt_read", fn_name="trace_wiredtiger_read_return")
            self.bpf.attach_kprobe(event="__wt_write", fn_name="trace_wiredtiger_write_entry")
            self.bpf.attach_kretprobe(event="__wt_write", fn_name="trace_wiredtiger_write_return")
            
            # Attach kprobes for network operations
            self.bpf.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
            self.bpf.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg")
            self.bpf.attach_kretprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg_return")
            
            # Try to attach USDT probes if available
            try:
                self.bpf.attach_uprobe(name="mongod", sym="mongo::ServiceEntryPointCommon::handleRequest", 
                                      fn_name="mongodb_query_start")
                self.bpf.attach_uretprobe(name="mongod", sym="mongo::ServiceEntryPointCommon::handleRequest", 
                                         fn_name="mongodb_query_end")
                print("Attached USDT probes for MongoDB query monitoring")
            except Exception as e:
                print(f"Could not attach USDT probes, falling back to function probes: {e}")
                try:
                    # Alternative approach: attach to WiredTiger operation functions
                    self.bpf.attach_uprobe(name="mongod", sym="_ZN5mongo16OperationContext11setDeadlineExx", 
                                          fn_name="mongodb_query_start")
                    self.bpf.attach_uretprobe(name="mongod", sym="_ZN5mongo16OperationContext11setDeadlineExx", 
                                             fn_name="mongodb_query_end")
                    print("Attached function probes for MongoDB query monitoring")
                except Exception as inner_e:
                    print(f"Could not attach function probes: {inner_e}")
            
            print("eBPF program loaded successfully")
            return True
        except Exception as e:
            print(f"Error loading eBPF program: {e}")
            return False

    def process_ebpf_events(self):
        def _process_query_event(cpu, data, size):
            event = self.bpf["mongodb_query_events"].event(data)
            
            # Convert nanoseconds to seconds for Prometheus
            duration_seconds = event.duration_ns / 1e9
            
            # Get operation name
            op_names = ["find", "insert", "update", "delete", "aggregate", "other"]
            op_name = op_names[event.operation] if event.operation < len(op_names) else "unknown"
            
            # Update Prometheus metrics
            collection = event.collection.decode('utf-8', 'replace').strip('\x00')
            self.prom_metrics['query_duration'].labels(collection=collection, operation=op_name).observe(duration_seconds)
            self.prom_metrics['docs_examined'].labels(collection=collection).inc(event.docs_examined)
            self.prom_metrics['docs_returned'].labels(collection=collection).inc(event.docs_returned)
            self.prom_metrics['collection_ops'].labels(collection=collection, operation=op_name).inc()
            
            # Log the event
            timestamp = datetime.fromtimestamp(event.timestamp / 1e9).strftime('%Y-%m-%d %H:%M:%S.%f')
            log_entry = {
                "timestamp": timestamp,
                "pid": event.pid,
                "collection": collection,
                "operation": op_name,
                "duration_ms": event.duration_ns / 1e6,
                "docs_examined": event.docs_examined,
                "docs_returned": event.docs_returned
            }
            
            with open(f"{self.output_dir}/query_events.jsonl", "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        
        def _process_io_event(cpu, data, size):
            event = self.bpf["mongodb_io_events"].event(data)
            
            # Update Prometheus metrics
            op_type = "read" if event.operation == ord('r') else "write"
            self.prom_metrics['io_bytes'].labels(operation=op_type).inc(event.bytes)
            
            # Log the event
            timestamp = datetime.fromtimestamp(event.timestamp / 1e9).strftime('%Y-%m-%d %H:%M:%S.%f')
            log_entry = {
                "timestamp": timestamp,
                "pid": event.pid,
                "operation": op_type,
                "bytes": event.bytes
            }
            
            with open(f"{self.output_dir}/io_events.jsonl", "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        
        def _process_net_event(cpu, data, size):
            event = self.bpf["mongodb_net_events"].event(data)
            
            # Update Prometheus metrics
            direction = "ingress" if event.direction == ord('i') else "egress"
            self.prom_metrics['net_bytes'].labels(direction=direction).inc(event.bytes)
            
            # Log the event
            timestamp = datetime.fromtimestamp(event.timestamp / 1e9).strftime('%Y-%m-%d %H:%M:%S.%f')
            log_entry = {
                "timestamp": timestamp,
                "pid": event.pid,
                "port": event.dport,
                "direction": direction,
                "bytes": event.bytes
            }
            
            with open(f"{self.output_dir}/net_events.jsonl", "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        
        # Open or create log files
        for log_file in ["query_events.jsonl", "io_events.jsonl", "net_events.jsonl"]:
            with open(f"{self.output_dir}/{log_file}", "w") as f:
                pass  # Just create/truncate the file
        
        # Register event callbacks
        self.bpf["mongodb_query_events"].open_perf_buffer(_process_query_event)
        self.bpf["mongodb_io_events"].open_perf_buffer(_process_io_event)
        self.bpf["mongodb_net_events"].open_perf_buffer(_process_net_event)
    
    def collect_mongodb_metrics(self):
        if not self.mongo_client:
            return
        
        try:
            # Get server status
            server_status = self.mongo_client.admin.command('serverStatus')
            
            # Update connections metrics
            connections = server_status.get('connections', {})
            for state, count in connections.items():
                if isinstance(count, (int, float)):
                    self.prom_metrics['connections'].labels(state=state).set(count)
            
            # Update memory metrics
            mem = server_status.get('mem', {})
            for mem_type, value in mem.items():
                if isinstance(value, (int, float)):
                    self.prom_metrics['memory_usage'].labels(type=mem_type).set(value * 1024 * 1024 if mem_type == 'resident' else value)
            
            # Update lock metrics
            locks = server_status.get('locks', {})
            for db_name, lock_types in locks.items():
                for lock_type, lock_info in lock_types.items():
                    if isinstance(lock_info, dict) and 'acquireCount' in lock_info:
                        self.prom_metrics['locks'].labels(database=db_name, type=lock_type).set(lock_info['acquireCount'])
            
            # Collect MongoDB process metrics using psutil
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                if 'mongod' in proc.info['name']:
                    # Get CPU usage
                    try:
                        cpu_percent = proc.cpu_percent(interval=None)
                        self.prom_metrics['cpu_usage'].set(cpu_percent)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    break
            
            # Log server status
            with open(f"{self.output_dir}/server_status.jsonl", "a") as f:
                f.write(json.dumps({
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "server_status": server_status
                }) + "\n")
                
        except Exception as e:
            print(f"Error collecting MongoDB metrics: {e}")

    def generate_reports(self):
        try:
            # Read event data
            query_df = pd.read_json(f"{self.output_dir}/query_events.jsonl", lines=True)
            io_df = pd.read_json(f"{self.output_dir}/io_events.jsonl", lines=True)
            net_df = pd.read_json(f"{self.output_dir}/net_events.jsonl", lines=True)
            
            if not query_df.empty:
                # Query duration by collection and operation
                plt.figure(figsize=(12, 6))
                query_df.groupby(['collection', 'operation'])['duration_ms'].mean().unstack().plot(kind='bar')
                plt.title('Average Query Duration by Collection and Operation')
                plt.ylabel('Duration (ms)')
                plt.tight_layout()
                plt.savefig(f"{self.output_dir}/query_duration.png")
                
                # Documents examined vs returned
                plt.figure(figsize=(12, 6))
                query_df.groupby('collection')[['docs_examined', 'docs_returned']].sum().plot(kind='bar')
                plt.title('Documents Examined vs Returned by Collection')
                plt.ylabel('Count')
                plt.tight_layout()
                plt.savefig(f"{self.output_dir}/docs_examined_vs_returned.png")
            
            if not io_df.empty:
                # I/O operations by type
                plt.figure(figsize=(12, 6))
                io_df.groupby('operation')['bytes'].sum().plot(kind='pie', autopct='%1.1f%%')
                plt.title('I/O Operations by Type (bytes)')
                plt.ylabel('')
                plt.tight_layout()
                plt.savefig(f"{self.output_dir}/io_operations.png")
            
            if not net_df.empty:
                # Network traffic by direction
                plt.figure(figsize=(12, 6))
                net_df.groupby('direction')['bytes'].sum().plot(kind='pie', autopct='%1.1f%%')
                plt.title('Network Traffic by Direction (bytes)')
                plt.ylabel('')
                plt.tight_layout()
                plt.savefig(f"{self.output_dir}/network_traffic.png")
            
            print(f"Reports generated in {self.output_dir}")
            
        except Exception as e:
            print(f"Error generating reports: {e}")

    def start_monitoring(self):
        if not self.connect_to_mongodb():
            print("Failed to connect to MongoDB, exiting")
            return
        
        if not self.load_ebpf_program():
            print("Failed to load eBPF program, exiting")
            return
        
        self.process_ebpf_events()
        
        self.running = True
        print("MongoDB monitoring started. Press Ctrl+C to stop.")
        
        try:
            while self.running:
                self.bpf.perf_buffer_poll(timeout=1000)
                self.collect_mongodb_metrics()
                time.sleep(10)  # Collect MongoDB metrics every 10 seconds
        except KeyboardInterrupt:
            print("Monitoring stopped by user")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        self.running = False
        print("Generating final reports...")
        self.generate_reports()
        print("MongoDB monitoring stopped")
        
        if self.mongo_client:
            self.mongo_client.close()
        
        if self.bpf:
            pass  # BPF object will be garbage collected

def main():
    parser = argparse.ArgumentParser(description="MongoDB eBPF Performance Monitoring")
    parser.add_argument("--uri", default="mongodb://localhost:27017", 
                        help="MongoDB connection URI")
    parser.add_argument("--output", default="./mongodb_metrics", 
                        help="Output directory for metrics and reports")
    parser.add_argument("--duration", type=int, default=0, 
                        help="Duration in seconds to run monitoring (0 for indefinite)")
    
    args = parser.parse_args()
    
    monitor = MongoDBEBPFMonitor(mongo_uri=args.uri, output_dir=args.output)
    
    if args.duration > 0:
        def stop_after_duration(seconds):
            time.sleep(seconds)
            monitor.stop_monitoring()
            print(f"Monitoring stopped after {seconds} seconds")
            os.kill(os.getpid(), signal.SIGINT)
        
        from threading import Thread
        Thread(target=stop_after_duration, args=(args.duration,), daemon=True).start()
    
    monitor.start_monitoring()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root. Try using sudo.")
        sys.exit(1)
    
    main()
