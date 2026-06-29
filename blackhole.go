package fastnetmon

import (
	"fmt"

	"github.com/levigross/grequests"
)

// Blocks some specified blackhole host
func (client *FastNetMonClient) BlackholeRemote(ip_address string) (bool, error) {
	resp, err := grequests.Put(client.Prefix+"/remote_blackhole/"+ip_address, grequests.FromRequestOptions(client.Ro))

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

// Returns all IPs blocked using remote blackhole
func (client *FastNetMonClient) GetRemoteBlackhole() ([]BlackholeAnnounces, error) {
	resp, err := grequests.Get(client.Prefix+"/remote_blackhole", grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return nil, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return nil, apiStatusError(resp)
	}

	ban_list_response := ResponseRemoteBlackholeListJson{}
	err = decodeResponseJSON(resp, &ban_list_response)
	if err != nil {
		return nil, err
	}

	return ban_list_response.Values, nil
}

// Removes remote blackhole entry using UUID
func (client *FastNetMonClient) RemoveRemoteBlackhole(mitigation_uuid string) (bool, error) {
	resp, err := grequests.Delete(client.Prefix+"/remote_blackhole/"+mitigation_uuid, grequests.FromRequestOptions(client.Ro))

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
