package fastnetmon

import (
	"fmt"

	"github.com/levigross/grequests"
)

// Adds Flow Spec announce
func (client *FastNetMonClient) AddFlowSpecRule(flow_spec_rule FlowSpecRule) (bool, error) {
	request_options := client.Ro

	request_options.JSON = flow_spec_rule

	resp, err := grequests.Put(client.Prefix+"/flowspec", grequests.FromRequestOptions(client.Ro))

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

// Returns all active flow spec announces
func (client *FastNetMonClient) GetFlowSpecRules() ([]ResponseFlowSpecAnnounce, error) {
	resp, err := grequests.Get(client.Prefix+"/flowspec", grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return nil, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return nil, apiStatusError(resp)
	}

	flow_spec_response := ResponseFlowSpecJson{}
	err = decodeResponseJSON(resp, &flow_spec_response)
	if err != nil {
		return nil, err
	}

	return flow_spec_response.Values, nil
}

// Removes Flow Spec entry using UUID
func (client *FastNetMonClient) RemoveFlowSpecRule(mitigation_uuid string) (bool, error) {
	resp, err := grequests.Delete(client.Prefix+"/flowspec/"+mitigation_uuid, grequests.FromRequestOptions(client.Ro))

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
