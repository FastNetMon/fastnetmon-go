package fastnetmon

import (
	"fmt"
	"strings"

	"errors"

	"github.com/levigross/grequests"
)

// JSON based callback script: https://fastnetmon.com/fastnetmon-json-formats/
type CallbackDetails struct {
	// For IPv4 "127.0.0.1"
	// For IPv6 "2a03:5131....:1"
	IP string `json:"ip"`

	// ban, unban, partial_block
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

	// Arbitrary string
	AttackType string `json:"attack_type"`

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

	// Incoming, outgoing or unknown. Deprecated field, please use AttackDetectionThresholdDirection instead
	AttackDirection string `json:"attack_direction"`

	// tcp, udp, icmp, unknown
	AttackProtocol string `json:"attack_protocol"`

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
	Protocol string `json"protocol"`
}

type ResponseArrayJson struct {
	Success   bool     `json:"success"`
	ErrorText string   `json:"error_text"`
	Values    []string `json:"values"`
}

type ErrorJson struct {
	Success   bool   `json:"success"`
	ErrorText string `json:"error_text"`
}

type ResponseJson struct {
	Success   bool   `json:"success"`
	ErrorText string `json:"error_text"`
	Value     string `json:"value"`
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

type FastNetMonClient struct {
	User     string `json:"api_user"`
	Password string `json:"api_password"`
	Host     string `json:"api_host"`
	Port     uint32 `json:"api_port"`
	Ro       *grequests.RequestOptions
	Prefix   string
}

// Creates new client, just checks input, does not execute connection attemps
func NewClient(host string, port uint32, user, password string) (*FastNetMonClient, error) {
	client := FastNetMonClient{}

	client.User = user
	client.Password = password
	client.Host = host
	client.Port = port

	if user != "" && password != "" && host != "" && port != 0 {
		client.Ro = &grequests.RequestOptions{Auth: []string{client.User, client.Password}}
		client.Prefix = fmt.Sprintf("http://%s:%d", client.Host, client.Port)

		return &client, nil
	}

	return nil, errors.New("Please provide all fields")
}

// Set specified bool option for host group
func (client *FastNetMonClient) SetBoolOptionHostGroup(hostgroup_name string, option_name string, value bool) (bool, error) {
	value_string := "disable"

	if value {
		value_string = "enable"
	}

	resp, err := grequests.Put(client.Prefix+"/hostgroup/"+hostgroup_name+"/"+option_name+"/"+value_string, client.Ro)

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return false, errors.New("Auth denied")
		} else {
			return false, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	response := ErrorJson{}
	err = resp.JSON(&response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Set specified string list option for host group
func (client *FastNetMonClient) SetStringListOptionHostGroup(hostgroup_name string, option_name string, value string) (bool, error) {
	// Replace prohibited symbols
	value = strings.Replace(value, "/", "%2f", -1)

	resp, err := grequests.Put(client.Prefix+"/hostgroup/"+hostgroup_name+"/"+option_name+"/"+value, client.Ro)

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return false, errors.New("Auth denied")
		} else {
			return false, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	response := ErrorJson{}
	err = resp.JSON(&response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Set specified int option for host group
func (client *FastNetMonClient) SetUnsignedIntegerOptionHostGroup(hostgroup_name string, option_name string, value uint) (bool, error) {
	resp, err := grequests.Put(client.Prefix+"/hostgroup/"+hostgroup_name+"/"+option_name+"/"+fmt.Sprintf("%d", value), client.Ro)

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return false, errors.New("Auth denied")
		} else {
			return false, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	response := ErrorJson{}
	err = resp.JSON(&response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Creates host groups with specified name
func (client *FastNetMonClient) CreateHostGroup(name string) (bool, error) {
	resp, err := grequests.Put(client.Prefix+"/hostgroup/"+name, client.Ro)

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return false, errors.New("Auth denied")
		} else {
			return false, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	response := ErrorJson{}
	err = resp.JSON(&response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Removes host group by name
func (client *FastNetMonClient) RemoveHostGroup(name string) (bool, error) {
	resp, err := grequests.Delete(client.Prefix+"/hostgroup/"+name, client.Ro)

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return false, errors.New("Auth denied")
		} else {
			return false, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	response := ErrorJson{}
	err = resp.JSON(&response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Blocks some specified blackhole host
func (client *FastNetMonClient) BlackholeRemote(ip_address string) (bool, error) {
	resp, err := grequests.Put(client.Prefix+"/remote_blackhole/"+ip_address, client.Ro)

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return false, errors.New("Auth denied")
		} else {
			return false, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	response := ErrorJson{}
	err = resp.JSON(&response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Returns all IPs blocked using remote blackhole
func (client *FastNetMonClient) GetRemoteBlackhole() ([]BlackholeAnnounces, error) {
	resp, err := grequests.Get(client.Prefix+"/remote_blackhole", client.Ro)

	if err != nil {
		return nil, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return nil, errors.New("Auth denied")
		} else {
			return nil, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	ban_list_response := ResponseRemoteBlackholeListJson{}
	err = resp.JSON(&ban_list_response)

	if err != nil {
		return nil, err
	}

	return ban_list_response.Values, nil
}

// Removes remote blackhole entry using UUID
func (client *FastNetMonClient) RemoveRemoteBlackhole(mitigation_uuid string) (bool, error) {
	resp, err := grequests.Delete(client.Prefix+"/remote_blackhole/"+mitigation_uuid, client.Ro)

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return false, errors.New("Auth denied")
		} else {
			return false, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	response := ErrorJson{}
	err = resp.JSON(&response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Returns all networks known by FastNetMon
func (client *FastNetMonClient) GetNetworks() ([]string, error) {
	resp, err := grequests.Get(client.Prefix+"/main/networks_list", client.Ro)

	if err != nil {
		return nil, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return nil, errors.New("Auth denied")
		} else {
			return nil, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	networks_response := ResponseArrayJson{}
	err = resp.JSON(&networks_response)

	if err != nil {
		return nil, err
	}

	return networks_response.Values, nil
}

// Retrieves all host groups
func (client *FastNetMonClient) GetAllHostgroups() ([]Ban_settings_t, error) {
	resp, err := grequests.Get(client.Prefix+"/hostgroup", client.Ro)

	if err != nil {
		return nil, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		if resp.StatusCode == 401 {
			return nil, errors.New("Auth denied")
		} else {
			return nil, fmt.Errorf("Did not return OK: %w", resp.StatusCode)
		}
	}

	hostgroups_response := ResponseHostGroupConfigurationJson{}
	err = resp.JSON(&hostgroups_response)

	if err != nil {
		return nil, err
	}

	return hostgroups_response.Values, nil
}

// Creates specified host group with all fields
// TODO: it does not implement all options, only required subset
func Create_host_group_with_all_options(fastnetmon_client *FastNetMonClient, new_host_group Ban_settings_t) error {
	new_host_group_name := new_host_group.Name

	add_success, err := fastnetmon_client.CreateHostGroup(new_host_group_name)

	if err != nil {
		return fmt.Errorf("Cannot create hostgroup '%+v' with error: %w", new_host_group, err)
	}

	if !add_success {
		return fmt.Errorf("Cannot create host group for some reasons")
	}

	enable_ban_res, err := fastnetmon_client.SetBoolOptionHostGroup(new_host_group_name, "enable_ban", new_host_group.Enable_ban)

	if err != nil {
		return fmt.Errorf("Cannot set bool variable: %+v", err)
	}

	if !enable_ban_res {
		return fmt.Errorf("Cannot set bool variable for some reasons")
	}

	// Add networks
	for _, network := range new_host_group.Networks {
		add_network, err := fastnetmon_client.SetStringListOptionHostGroup(new_host_group_name, "networks", network)

		if err != nil {
			return fmt.Errorf("Cannot add network: %w", err)
		}

		if !add_network {
			return fmt.Errorf("Cannot add network")
		}
	}

	enable_bandwidth_ban, err := fastnetmon_client.SetBoolOptionHostGroup(new_host_group_name, "ban_for_bandwidth", new_host_group.Ban_for_bandwidth)

	if err != nil {
		return fmt.Errorf("Cannot set bool variable: %+v", err)
	}

	if !enable_bandwidth_ban {
		return fmt.Errorf("Cannot set bool variable for some reasons")
	}

	enable_pps_ban, err := fastnetmon_client.SetBoolOptionHostGroup(new_host_group_name, "ban_for_pps", new_host_group.Ban_for_pps)

	if err != nil {
		return fmt.Errorf("Cannot set bool variable: %+v", err)
	}

	if !enable_pps_ban {
		return fmt.Errorf("Cannot set bool variable for some reasons")
	}

	enable_flow_ban, err := fastnetmon_client.SetBoolOptionHostGroup(new_host_group_name, "ban_for_flows", new_host_group.Ban_for_flows)

	if err != nil {
		return fmt.Errorf("Cannot set bool variable: %+v", err)
	}

	if !enable_flow_ban {
		return fmt.Errorf("Cannot set bool variable for some reasons")
	}

	bandwidth_threshold, err := fastnetmon_client.SetUnsignedIntegerOptionHostGroup(new_host_group_name, "threshold_mbps", new_host_group.Threshold_mbps)

	if err != nil {
		return fmt.Errorf("Cannot set threshold value variable: %+v", err)
	}

	if !bandwidth_threshold {
		return fmt.Errorf("Cannot set bandwidth threshold")
	}

	packet_threshold, err := fastnetmon_client.SetUnsignedIntegerOptionHostGroup(new_host_group_name, "threshold_pps", new_host_group.Threshold_pps)

	if err != nil {
		return fmt.Errorf("Cannot set threshold value variable: %+v", err)
	}

	if !packet_threshold {
		return fmt.Errorf("Cannot set packet per second threshold")
	}

	flow_threshold, err := fastnetmon_client.SetUnsignedIntegerOptionHostGroup(new_host_group_name, "threshold_flows", new_host_group.Threshold_flows)

	if err != nil {
		return fmt.Errorf("Cannot set threshold value variable: %+v", err)
	}

	if !flow_threshold {
		return fmt.Errorf("Cannot set flow threshold")
	}

	return nil
}
