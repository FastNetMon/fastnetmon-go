package fastnetmon

// JSON based callback script: https://fastnetmon.com/fastnetmon-json-formats/
type CallbackDetails struct {
	// For IPv4 "127.0.0.1"
	// For IPv6 "2a03:5131....:1"
	IP string `json:"ip"`

	// ban, unban, attack_status, partial_block, partial_unblock
	Action string `json:"action"`

	AttackDetails CallbackAttackDetails `json:"attack_details"`

	// Callback type: host or hostgroup
	AlertScope string `json:"alert_scope"`

	// We populate it only for AlertScope set to hostgroup
	HostGroup string `json:"hostgroup_name"`

	// We populate it only for AlertScope set to hostgroup
	ParentHostGroup string `json:"parent_hostgroup_name"`

	// List of networks which belong to hostgroup
	HostGroupNetworks []string `json:"hostgroup_networks"`

	// Packet dump in string format for "ban" action only:
	// "2018-12-15 19:16:39.376373 127.0.0.10:0 > 127.0.0.1:8842 protocol: tcp flags: rst,ack frag: 0  packets: 1 size: 54 bytes ip size: 40 bytes ttl: 64 sample ratio: 1 ",
	PacketDump []string `json:"packet_dump"`

	// Detailed packet dump in parsed format
	PacketDumpDetailed []CallbackPacketDumpEntry `json:"packet_dump_detailed"`

	// BGP Flow Spec rules
	FlowSpecRules []FlowSpecRule `json:"flow_spec_rules"`
}
type FlowSpecAction struct {
	// Rate
	Rate uint `json:"rate"`
}

type FlowSpecRule struct {
	// IPv4 network in CIDR format, optional field
	SourcePrefix string `json:"source_prefix,omitempty"`

	// IPv4 network in CIDR format, optional field
	DestinationPrefix string `json:"destination_prefix,omitempty"`

	// List of destination ports (from 0 to 65535), optional field
	DestinationPorts []uint `json:"destination_ports,omitempty"`

	// List of source ports (from 0 to 65535), optional field
	SourcePorts []uint `json:"source_ports,omitempty"`

	// List of packet sizes (from 0 to 1500), optional field
	PacketLengths []uint `json:"packet_lengths,omitempty"`

	// List of protocols (allowed options udp, tcp, icmp, gre), optional field
	Protocols []string `json:"protocols,omitempty"`

	// List of fragmentation flags (allowed values: dont-fragment, is-fragment, first-fragment, last-fragment, not-a-fragment), optional field
	FragmentationFlags []string `json:"fragmentation_flags,omitempty"`

	// List of TCP flags, allowed only when TCP used in protocols list. Allowed values: syn, ack, fin, urgent, push, rst. Flags also could be mixed with "|" sign (tcp|push). Optional field
	TcpFlags []string `json:"tcp_flags,omitempty"`

	// List of TTLs for traffic matching, non RFC compliant addition
	Ttls []uint `json:"ttls,omitempty"`

	// List of vlans for traffic matching, non RFC compliant addition
	Vlans []uint `json:"vlans,omitempty"`

	// Action type, allowed values: accept, discard, rate-limit, redirect, mark
	ActionType string `json:"action_type,omitempty"`

	// Optional details specific for action
	Action FlowSpecAction `json:"action,omitempty"`

	// List of IPs which can be used when action is set to "accept" to forward traffic to them
	IPv4NextHops []string `json:"ipv4_nexthops,omitempty"`
}

// Keeps fields specific for threshold
type ThresholdStructure struct {
	Flows   bool `json:"flows"`
	Mbits   bool `json:"mbits"`
	Packets bool `json:"packets"`
}

// FlexibleThresholdsDetails keeps details about which flexible thresholds triggered attack
// In some cases incoming and outgoing both can be true when attack was triggered in both directions in same time
type FlexibleThresholdsDetails struct {
	// Set when attack was triggered in incoming direction
	Incoming bool `json:"incoming"`
	// Set when attack was triggered in outgoing direction
	Outgoing        bool               `json:"outgoing"`
	IncomingDetails ThresholdStructure `json:"incoming_details"`
	OutgoingDetails ThresholdStructure `json:"outgoing_details"`
}

// Key information about attack
type CallbackAttackDetails struct {
	// Example: 041eb504-2b33-4ff7-a6b7-8235408d5062
	AttackUUID string `json:"attack_uuid"`

	// low, middle, high, unknown
	AttackSeverity string `json:"attack_severity"`

	// Hostgroup name, only for per host callbacks
	HostGroup string `json:"host_group"`

	// Parent hostgroup name, only for per host callbacks
	ParentHostGroup string `json:"parent_host_group"`

	// Host's network, only for per host callbacks
	HostNetwork string `json:"host_network"`

	// IPv4 or IPv6
	ProtocolVersion string `json:"protocol_version"`

	// Set to true when attack was triggered by flexible threshold
	AttackDetectionTriggeredByFlexibleThreshold bool `json:"attack_detection_triggered_by_flexible_threshold"`

	// List of flexible thresholds which triggered attack
	AttackDetectionFlexibleThresholds []string `json:"attack_detection_flexible_thresholds"`

	// Detailed information about thresholds which triggered attack
	Attack_DetectionFlexibleThresholdsDetailed map[string]FlexibleThresholdsDetails `json:"attack_detection_flexible_thresholds_detailed"`

	AttackDetectionThreshold          string `json:"attack_detection_threshold"`
	AttackDetectionThresholdDirection string `json:"attack_detection_threshold_direction"`

	// automatic, manual, other
	AttackDetectionSource string `json:"attack_detection_source"`

	TotalIncomingTraffic uint64 `json:"total_incoming_traffic"`
	TotalOutgoingTraffic uint64 `json:"total_outgoing_traffic"`
	TotalIncomingPps     uint64 `json:"total_incoming_pps"`
	TotalOutgoingPps     uint64 `json:"total_outgoing_pps"`

	TotalIncomingFlows uint64 `json:"total_incoming_flows"`
	TotalOutgoingFlows uint64 `json:"total_outgoing_flows"`

	IncomingIPFragmentedTraffic uint64 `json:"incoming_ip_fragmented_traffic"`
	OutgoingIPFragmentedTraffic uint64 `json:"outgoing_ip_fragmented_traffic"`
	IncomingIPFragmentedPps     uint64 `json:"incoming_ip_fragmented_pps"`
	OutgoingIPFragmentedPps     uint64 `json:"outgoing_ip_fragmented_pps"`

	IncomingTCPTraffic uint64 `json:"incoming_tcp_traffic"`
	OutgoingTCPTraffic uint64 `json:"outgoing_tcp_traffic"`
	IncomingTCPPps     uint64 `json:"incoming_tcp_pps"`
	OutgoingTCPPps     uint64 `json:"outgoing_tcp_pps"`

	IncomingSYNTCPTraffic uint64 `json:"incoming_syn_tcp_traffic"`
	OutgoingSYNTCPTraffic uint64 `json:"outgoing_syn_tcp_traffic"`
	IncomingSYNTCPPps     uint64 `json:"incoming_syn_tcp_pps"`
	OutgoingSYNTCPPps     uint64 `json:"outgoing_syn_tcp_pps"`

	IncomingUDPTraffic uint64 `json:"incoming_udp_traffic"`
	OutgoingUDPTraffic uint64 `json:"outgoing_udp_traffic"`
	IncomingUDPPps     uint64 `json:"incoming_udp_pps"`
	OutgoingUDPPps     uint64 `json:"outgoing_udp_pps"`

	IncomingICMPTraffic uint64 `json:"incoming_icmp_traffic"`
	OutgoingICMPTraffic uint64 `json:"outgoing_icmp_traffic"`
	IncomingICMPPps     uint64 `json:"incoming_icmp_pps"`
	OutgoingICMPPps     uint64 `json:"outgoing_icmp_pps"`
}

// Detailed per field packet dump entry
type CallbackPacketDumpEntry struct {
	// ipv4 or ipv6
	IPVersion string `json:"ip_version"`

	// IPs represented as strings
	SourceIP      string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`

	// Applicable only for TCP and UDP
	SourcePort      uint64 `json:"source_port"`
	DestinationPort uint64 `json:"destination_port"`

	// TCP Flags as string
	TCPFlags string `json:"tcp_flags"`

	Fragmentation bool   `json:"fragmentation"`
	Packets       uint64 `json:"packets"`
	Length        uint64 `json:"length"`
	IPLength      uint64 `json:"ip_length"`
	TTL           uint64 `json:"ttl"`
	SampleRatio   uint64 `json:"sample_ratio"`

	// tcp, udp, icmp and unknown
	Protocol string `json:"protocol"`

	// Address of device which sent this flow / packet
	AgentAddress string `json:"agent_address"`
}

// Wrapper structure to carry Flow Spec announce and it's UUID
type ResponseFlowSpecAnnounce struct {
	UUID     string       `json:"uuid"`
	Announce FlowSpecRule `json:"announce"`
}

type ResponseFlowSpecJson struct {
	Success bool                       `json:"success"`
	Values  []ResponseFlowSpecAnnounce `json:"values"`
}

type ResponseHostGroupConfigurationJson struct {
	Success   bool             `json:"success"`
	ErrorText string           `json:"error_text"`
	Values    []Ban_settings_t `json:"values"`
}

type BlackholeAnnounces struct {
	UUID string `json:"uuid"`
	IP   string `json:"ip"`
}

type ResponseRemoteBlackholeListJson struct {
	Success   bool                 `json:"success"`
	ErrorText string               `json:"error_text"`
	Values    []BlackholeAnnounces `json:"values"`
}

type Ban_settings_t struct {
	Name                   string   `bson:"name" json:"name" fastnetmon_type:"string"`
	Description            string   `bson:"description" json:"description" fastnetmon_type:"string"`
	Networks               []string `bson:"networks" json:"networks" fastnetmon_type:"cidr_networks_list"`
	Enable_ban             bool     `bson:"enable_ban" json:"enable_ban" fastnetmon_type:"bool"`
	Enable_ban_incoming    bool     `bson:"enable_ban_incoming" json:"enable_ban_incoming" fastnetmon_type:"bool"`
	Enable_ban_outgoing    bool     `bson:"enable_ban_outgoing" json:"enable_ban_outgoing" fastnetmon_type:"bool"`
	Calculation_method     string   `bson:"calculation_method" json:"calculation_method" fastnetmon_type:"string"`
	Ban_for_pps            bool     `bson:"ban_for_pps" json:"ban_for_pps" fastnetmon_type:"bool"`
	Ban_for_bandwidth      bool     `bson:"ban_for_bandwidth" json:"ban_for_bandwidth" fastnetmon_type:"bool"`
	Ban_for_flows          bool     `bson:"ban_for_flows" json:"ban_for_flows" fastnetmon_type:"bool"`
	Threshold_pps          uint     `bson:"threshold_pps" json:"threshold_pps" fastnetmon_type:"positive_integer_without_zero"`
	Threshold_mbps         uint     `bson:"threshold_mbps" json:"threshold_mbps" fastnetmon_type:"positive_integer_without_zero"`
	Threshold_flows        uint     `bson:"threshold_flows" json:"threshold_flows" fastnetmon_type:"positive_integer_without_zero"`
	Ban_for_tcp_bandwidth  bool     `bson:"ban_for_tcp_bandwidth" json:"ban_for_tcp_bandwidth" fastnetmon_type:"bool"`
	Ban_for_udp_bandwidth  bool     `bson:"ban_for_udp_bandwidth" json:"ban_for_udp_bandwidth" fastnetmon_type:"bool"`
	Ban_for_icmp_bandwidth bool     `bson:"ban_for_icmp_bandwidth" json:"ban_for_icmp_bandwidth" fastnetmon_type:"bool"`
	Ban_for_tcp_pps        bool     `bson:"ban_for_tcp_pps" json:"ban_for_tcp_pps" fastnetmon_type:"bool"`
	Ban_for_udp_pps        bool     `bson:"ban_for_udp_pps" json:"ban_for_udp_pps" fastnetmon_type:"bool"`
	Ban_for_icmp_pps       bool     `bson:"ban_for_icmp_pps" json:"ban_for_icmp_pps" fastnetmon_type:"bool"`
	Threshold_tcp_mbps     uint     `bson:"threshold_tcp_mbps" json:"threshold_tcp_mbps" fastnetmon_type:"positive_integer_without_zero"`
	Threshold_udp_mbps     uint     `bson:"threshold_udp_mbps" json:"threshold_udp_mbps" fastnetmon_type:"positive_integer_without_zero"`
	Threshold_icmp_mbps    uint     `bson:"threshold_icmp_mbps" json:"threshold_icmp_mbps" fastnetmon_type:"positive_integer_without_zero"`
	Threshold_tcp_pps      uint     `bson:"threshold_tcp_pps" json:"threshold_tcp_pps" fastnetmon_type:"positive_integer_without_zero"`
	Threshold_udp_pps      uint     `bson:"threshold_udp_pps" json:"threshold_udp_pps" fastnetmon_type:"positive_integer_without_zero"`
	Threshold_icmp_pps     uint     `bson:"threshold_icmp_pps" json:"threshold_icmp_pps" fastnetmon_type:"positive_integer_without_zero"`
}
