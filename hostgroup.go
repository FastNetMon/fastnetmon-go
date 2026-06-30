package fastnetmon

import (
	"fmt"
	"strings"

	"github.com/levigross/grequests"
)

// Retrieves all host groups
func (client *FastNetMonClient) GetAllHostgroups() ([]Ban_settings_t, error) {
	resp, err := grequests.Get(client.Prefix+"/hostgroup", grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return nil, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return nil, apiStatusError(resp)
	}

	hostgroups_response := ResponseHostGroupConfigurationJson{}
	err = decodeResponseJSON(resp, &hostgroups_response)

	if err != nil {
		return nil, err
	}

	return hostgroups_response.Values, nil
}

// Creates host groups with specified name
func (client *FastNetMonClient) CreateHostGroup(name string) (bool, error) {
	resp, err := grequests.Put(client.Prefix+"/hostgroup/"+name, grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return false, apiStatusError(resp)
	}

	response := ErrorJson{}
	err = decodeResponseJSON(resp, &response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Removes host group by name
func (client *FastNetMonClient) RemoveHostGroup(name string) (bool, error) {
	resp, err := grequests.Delete(client.Prefix+"/hostgroup/"+name, grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return false, apiStatusError(resp)
	}

	response := ErrorJson{}
	err = decodeResponseJSON(resp, &response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Set specified bool option for host group
func (client *FastNetMonClient) SetBoolOptionHostGroup(hostgroup_name string, option_name string, value bool) (bool, error) {
	value_string := "disable"

	if value {
		value_string = "enable"
	}

	resp, err := grequests.Put(client.Prefix+"/hostgroup/"+hostgroup_name+"/"+option_name+"/"+value_string, grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return false, apiStatusError(resp)
	}

	response := ErrorJson{}
	err = decodeResponseJSON(resp, &response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Set specified string list option for host group
func (client *FastNetMonClient) SetStringListOptionHostGroup(hostgroup_name string, option_name string, value string) (bool, error) {
	// Replace prohibited symbols
	value = strings.Replace(value, "/", "%2f", -1)

	resp, err := grequests.Put(client.Prefix+"/hostgroup/"+hostgroup_name+"/"+option_name+"/"+value, grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return false, apiStatusError(resp)
	}

	response := ErrorJson{}
	err = decodeResponseJSON(resp, &response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
}

// Set specified int option for host group
func (client *FastNetMonClient) SetUnsignedIntegerOptionHostGroup(hostgroup_name string, option_name string, value uint) (bool, error) {
	resp, err := grequests.Put(client.Prefix+"/hostgroup/"+hostgroup_name+"/"+option_name+"/"+fmt.Sprintf("%d", value), grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return false, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return false, apiStatusError(resp)
	}

	response := ErrorJson{}
	err = decodeResponseJSON(resp, &response)

	if err != nil {
		return false, err
	}

	return response.Success, nil
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
