# MongoDB eBPF Monitoring Setup Guide

This guide will walk you through setting up the MongoDB eBPF monitoring infrastructure to troubleshoot performance issues and gain deep insights into MongoDB's behavior at the kernel level.

## Prerequisites

### System Requirements
- Linux kernel 4.18+ with BPF support enabled
- Root access (required for eBPF)
- Python 3.7+
- MongoDB 4.0+

### Required Packages

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-pip python3-dev

# RHEL/CentOS
sudo yum install -y bcc-tools kernel-devel-$(uname -r) python3-pip python3-devel

# Install required Python packages
sudo pip3 install bcc pymongo psutil pandas matplotlib prometheus_client
```

### Monitoring Infrastructure Components
- Prometheus (for metrics collection)
- Grafana (for visualization)

```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar xvfz prometheus-2.45.0.linux-amd64.tar.gz
cd prometheus-2.45.0.linux-amd64/
sudo mv prometheus /usr/local/bin/
sudo mv promtool /usr/local/bin/

# Install Grafana
sudo apt-get install -y apt-transport-https software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install -y grafana
```

## Installation Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/MinervaDB/ebpf-mongodb.git
   cd mongodb-ebpf-monitoring
   ```

2. **Configure Prometheus**
   
   Create a Prometheus configuration file at `/etc/prometheus/prometheus.yml`:
   
   ```yaml
   global:
     scrape_interval: 15s
   
   scrape_configs:
     - job_name: 'mongodb_ebpf'
       static_configs:
         - targets: ['localhost:8000']
   ```
   
   Start Prometheus:
   ```bash
   sudo prometheus --config.file=/etc/prometheus/prometheus.yml
   ```

3. **Configure Grafana**
   
   Copy the provided Grafana dashboard configuration:
   ```bash
   sudo mkdir -p /etc/grafana/provisioning/dashboards
   sudo cp dashboard.yml /etc/grafana/provisioning/dashboards/
   ```
   
   Start Grafana:
   ```bash
   sudo systemctl start grafana-server
   sudo systemctl enable grafana-server
   ```
   
   Access Grafana at http://localhost:3000 (default credentials: admin/admin)
   
   Add Prometheus as a data source:
   - Name: Prometheus
   - Type: Prometheus
   - URL: http://localhost:9090
   - Access: Server (default)

4. **Run the eBPF Monitoring Tool**
   
   ```bash
   sudo python3 mongodb_ebpf_monitor.py --uri mongodb://username:password@hostname:27017 --output /var/log/mongodb_metrics
   ```
   
   Optional parameters:
   - `--uri`: MongoDB connection URI (default: mongodb://localhost:27017)
   - `--output`: Directory to store metrics and reports (default: ./mongodb_metrics)
   - `--duration`: Duration in seconds to run monitoring (0 for indefinite)

## Understanding the Monitoring Infrastructure

### eBPF Probes

The monitoring infrastructure attaches eBPF probes to:

1. **MongoDB File Operations**
   - WiredTiger read/write operations
   - Journal writes
   - Filesystem operations

2. **Network Activity**
   - TCP send/receive operations
   - Connection handling
   - Request/response tracking

3. **MongoDB Query Execution**
   - Query parsing and planning
   - Index usage
   - Document examination and retrieval

4. **System-level Metrics**
   - CPU usage by thread
   - Memory allocations
   - Lock contentions

### Data Collection Flow

1. eBPF programs capture low-level events in the kernel
2. Events are processed and aggregated
3. Metrics are exposed via Prometheus
4. Grafana visualizes the metrics in real-time dashboards

### Metric Types

1. **Counters**
   - Operations by type/collection
   - Bytes read/written
   - Network traffic

2. **Gauges**
   - Connection counts
   - Memory usage
   - CPU utilization

3. **Histograms**
   - Query durations
   - I/O latencies
   - Lock wait times

4. **Derived Metrics**
   - Query efficiency (docs examined/returned ratio)
   - Cache hit ratio
   - Connection utilization

## Troubleshooting Common MongoDB Performance Issues

### Identifying Slow Queries

Look for:
- High values in "Query Duration by Collection" panel
- Collections with high documents examined to returned ratio
- Large spikes in disk I/O during specific operations

Solution approaches:
- Create indexes for frequently queried fields
- Restructure queries to use existing indexes
- Consider denormalizing frequently joined data

### Detecting I/O Bottlenecks

Look for:
- High disk read/write metrics
- Correlation between disk activity and query slowdowns
- Low cache hit ratios

Solution approaches:
- Increase WiredTiger cache size
- Consider faster storage (SSD/NVMe)
- Review MongoDB journaling settings
- Optimize collection schemas

### Network Performance Issues

Look for:
- High network bytes transferred
- Correlation between network spikes and slow operations
- Large response sizes

Solution approaches:
- Use projection to limit fields returned
- Implement pagination for large result sets
- Consider network hardware upgrades if consistently saturated

### Memory Pressure

Look for:
- High resident memory usage
- Frequent page faults
- Low WiredTiger cache hit rate

Solution approaches:
- Increase available RAM
- Tune WiredTiger cache settings
- Review MongoDB memory-mapped settings

### Connection Issues

Look for:
- High connection utilization percentage
- Connection count approaching maximum
- Correlation between performance drops and connection spikes

Solution approaches:
- Implement connection pooling
- Increase maximum allowed connections
- Check for connection leaks in application code

## Advanced Usage

### Custom Metrics

You can extend the eBPF monitoring program to track additional metrics by:

1. Adding new data structures to the BPF C program
2. Creating new event processing functions
3. Adding Prometheus metrics for the new events

Example of adding a new metric for tracking query queue time:

```python
# In the MongoDBEBPFMonitor class
self.prom_metrics['query_queue_time'] = Histogram(
    'mongodb_query_queue_time_seconds', 
    'Time queries spend in queue before execution',
    ['collection']
)

# Add corresponding BPF structures and event handlers
```

### Integration with Alerting Systems

Configure Grafana alerts based on thresholds:

1. Navigate to any panel in Grafana
2. Click "Edit" in the dropdown menu
3. Select "Alert" tab
4. Define conditions (e.g., "query duration > 1s for 5 minutes")
5. Add notification channels (email, Slack, PagerDuty, etc.)

## Troubleshooting the Monitoring Tool

### Common Issues and Solutions

1. **"Cannot find kernel headers" error**
   ```
   Solution: Install appropriate kernel headers
   sudo apt-get install linux-headers-$(uname -r)
   ```

2. **"Permission denied" error**
   ```
   Solution: Run with sudo or proper privileges
   sudo python3 mongodb_ebpf_monitor.py
   ```

3. **"Failed to attach kprobe" error**
   ```
   Solution: Check kernel compatibility and available kprobes
   sudo cat /proc/kallsyms | grep <function_name>
   ```

4. **Cannot connect to MongoDB**
   ```
   Solution: Verify URI and credentials
   python3 -c "import pymongo; pymongo.MongoClient('your-uri')"
   ```

5. **No data appearing in Grafana**
   ```
   Solution: Check Prometheus target status and scraping
   curl http://localhost:8000/metrics
   ```

### Getting Help

For additional assistance:
- Check the GitHub repository issues
- Join our community Discord/Slack
- Email support at support@example.com

## Extending the Solution

### Additional Monitoring Areas

Consider adding:
- Sharding-specific metrics
- Replication lag tracking
- Diagnostic data collection during performance incidents
- Automatic query analysis and index suggestion

### Integration with APM Tools

The eBPF monitoring can be integrated with:
- Datadog
- New Relic
- Elastic APM
- Dynatrace

by forwarding metrics via their respective APIs or exporters.

## Security Considerations

Since eBPF programs run with kernel privileges, ensure:
- Monitor is run in controlled environments
- Authentication credentials are handled securely
- Output files have appropriate permissions
- Monitoring server has limited network exposure

## License and Contributions

This project is licensed under the MIT License.

Contributions are welcome! Please feel free to submit pull requests or open issues on our GitHub repository.
