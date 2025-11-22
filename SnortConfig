# -------------------------------------------------------------------------
# SNORT CONFIGURATION FILE
# -------------------------------------------------------------------------

# =========================================================================
# 1. PATH CONFIGURATION
# =========================================================================

# Path to your rule files
var RULE_PATH /usr/local/snort/rules
# Path to your precompiled rules (if used)
var SO_RULE_PATH /usr/local/snort/so_rules
# Path to the Snort data files
var PREPROC_RULE_PATH /usr/local/snort/preproc_rules
# Path for dynamic libraries and engines
var DYNAMIC_PREPROCESSOR_PATH /usr/local/lib/snort_dynamicpreprocessor/
var DYNAMIC_ENGINE /usr/local/lib/snort_dynamicengine/sf_engine.so

# =========================================================================
# 2. NETWORK VARIABLES (REQUIRED PER PRD SECTION 2.2)
# You MUST modify these variables for your environment.
# =========================================================================

# Define your internal protected network (HOME_NET)
# e.g., 10.0.0.0/8, 192.168.1.0/24. Use commas for multiple subnets.
ipvar HOME_NET [10.0.0.0/8,192.168.1.0/24] 

# Define everything else as the external network (EXTERNAL_NET)
ipvar EXTERNAL_NET any

# Standard port variables
portvar HTTP_PORTS [80,8080]
portvar SHELLCODE_PORTS !21
# ... other standard port definitions

# =========================================================================
# 3. PREPROCESSORS (REQUIRED PER PRD SECTION 3.1)
# Must enable and tune for accurate protocol analysis.
# =========================================================================

# Stream5 (TCP Reassembly)
preprocessor stream5_global: max_tcp 262144, track_tcp yes, track_udp yes, track_icmp yes 
preprocessor stream5_ip: timeout 30, max_active_sessions 0 
preprocessor stream5_tcp: policy first, ports client all 

# HTTP Inspect
preprocessor http_inspect: \
    server_profile all \
    allow_proxy_post \
    server_body_limit 4294967295 \
    client_body_limit 4294967295

# DNS Preprocessor
preprocessor dns: enable_all 

# Frag3 (IP fragmentation detection)
preprocessor frag3_global: max_frags 65535, max_frag_bytes 10485760, enable_inline_ip_options
preprocessor frag3_engine: all

# =========================================================================
# 4. OUTPUT PLUGINS (REQUIRED PER PRD SECTION 4)
# =========================================================================

# A. Unified2 Logging (REQUIRED PER PRD SECTION 4.1)
# Unified2 format is used by Barnyard2 for SIEM integration.
output unified2: filename snort.log, limit 128, sensor_id 0

# B. Alerting to a Fast Log (optional, for quick viewing)
# output alert_fast: stdout

# C. Console Alerting
# output alert_console:

# =========================================================================
# 5. RULE SETS (REQUIRED PER PRD SECTION 3.2)
# =========================================================================

# Load Custom Rules (REQUIRED)
include $RULE_PATH/local.rules

# Load Snort Community Rules (REQUIRED)
include $RULE_PATH/community.rules

# Example of loading a specific rules file
# include $RULE_PATH/web-attacks.rules

# Load Subscription Rules (if licensed)
# include /etc/snort/rules/snort.rules

# =========================================================================
# 6. THRESHOLDING AND SUPPRESSION (PRD SECTION 3.3)
# Used to manage high-volume, low-priority alerts.
# =========================================================================

# Path to the suppression/threshold file
include /etc/snort/threshold.conf

# Example threshold.conf entries:
# threshold gen_id 1, sig_id 1851, type limit, track by_src, count 10, seconds 60
# suppress gen_id 1, sig_id 2000003, track by_src, ip 192.168.1.100

# =========================================================================
# 7. INTRUSION PREVENTION SYSTEM (IPS) MODE (PRD SECTION 2.1)
# Uncomment the following when transitioning from IDS to IPS mode.
# =========================================================================

# config daq: inline
# config policy_mode: inline

# -------------------------------------------------------------------------
# END OF CONFIGURATION
# -------------------------------------------------------------------------
