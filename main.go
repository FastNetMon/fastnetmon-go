package fastnetmon

import (
	"fmt"
	"net/url"
	"strings"

	"errors"

	"github.com/levigross/grequests"
)

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

func NewClientV2(host string, port uint32, user, password string, EnabledV2 bool, TLS bool, InsecureSkipVerify bool) (*FastNetMonClient, error) {
	client := FastNetMonClient{}

	client.User = user
	client.Password = password
	client.Host = host
	client.Port = port

	if user == "" && password == "" && host == "" && port == 0 {
		return nil, errors.New("Please provide all fields")
	}

	client.Ro = &grequests.RequestOptions{Auth: []string{client.User, client.Password}}

	proto := "http"
	if TLS {
		proto = "https"
		if InsecureSkipVerify {
			client.Ro.InsecureSkipVerify = true
		}
	}

	client.Prefix = fmt.Sprintf("%s://%s:%d", proto, client.Host, client.Port)
	if EnabledV2 {
		client.Prefix, _ = url.JoinPath(client.Prefix, "/api/v2")
	}

	return &client, nil

}

func apiStatusError(resp *grequests.Response) error {
	if resp.StatusCode == 401 {
		return errors.New("Auth denied")
	}

	responseBody := strings.TrimSpace(resp.String())
	if responseBody != "" {
		return fmt.Errorf("Did not return OK: %d, response: %s", resp.StatusCode, responseBody)
	}

	return fmt.Errorf("Did not return OK: %d", resp.StatusCode)
}

func decodeResponseJSON(response *grequests.Response, userStruct interface{}) (err error) {

	responseBody := strings.TrimSpace(response.String())
	err = response.JSON(&userStruct)
	if err != nil {
		responseBody = strings.ReplaceAll(responseBody, "\n", " ")
		if len(responseBody) > 31 {
			responseBody = responseBody[:30] + "..."
		}
		err = fmt.Errorf("Cannot parse output '%s' to json: %v", responseBody, err)
		return
	}
	return
}

// Returns all networks known by FastNetMon
func (client *FastNetMonClient) GetNetworks() ([]string, error) {
	resp, err := grequests.Get(client.Prefix+"/main/networks_list", grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return nil, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return nil, apiStatusError(resp)
	}

	networks_response := ResponseArrayJson{}

	err = decodeResponseJSON(resp, &networks_response)
	if err != nil {
		return nil, err
	}

	return networks_response.Values, nil
}

func (client *FastNetMonClient) AddNetwork(cidr string) error {
	encoded := strings.Replace(cidr, "/", "%2f", 1)
	resp, err := grequests.Put(client.Prefix+"/main/networks_list/"+encoded, grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return apiStatusError(resp)
	}

	response := ErrorJson{}
	err = decodeResponseJSON(resp, &response)
	if err != nil {
		return err
	}

	if !response.Success {
		return fmt.Errorf("API error: %s", response.ErrorText)
	}

	return nil
}

func (client *FastNetMonClient) RemoveNetwork(cidr string) error {
	encoded := strings.Replace(cidr, "/", "%2f", 1)
	resp, err := grequests.Delete(client.Prefix+"/main/networks_list/"+encoded, grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return apiStatusError(resp)
	}

	response := ErrorJson{}
	err = decodeResponseJSON(resp, &response)
	if err != nil {
		return err
	}

	if !response.Success {
		return fmt.Errorf("API error: %s", response.ErrorText)
	}

	return nil
}

func (client *FastNetMonClient) Commit() error {
	resp, err := grequests.Put(client.Prefix+"/commit", grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return apiStatusError(resp)
	}

	response := ErrorJson{}
	err = decodeResponseJSON(resp, &response)
	if err != nil {
		return err
	}

	if !response.Success {
		return fmt.Errorf("API error: %s", response.ErrorText)
	}

	return nil
}

func (client *FastNetMonClient) GetLicense() (info LicenseInfo, err error) {
	resp, err := grequests.Get(client.Prefix+"/license", grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return info, fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return info, apiStatusError(resp)
	}

	response := ResponseLicense{}
	err = decodeResponseJSON(resp, &response)
	info = response.Object
	if err != nil {
		return info, err
	}
	return info, nil
}

func (client *FastNetMonClient) GetVersion() (string, error) {
	resp, err := grequests.Get(client.Prefix+"/fastnetmon_version", grequests.FromRequestOptions(client.Ro))

	if err != nil {
		return "", fmt.Errorf("Cannot connect to API: %w", err)
	}

	if !resp.Ok {
		return "", apiStatusError(resp)
	}

	response := ResponseJson{}
	err = decodeResponseJSON(resp, &response)
	if err != nil {
		return "", err
	}
	if !response.Success {
		return "", fmt.Errorf("API error: %s", response.ErrorText)
	}
	return response.Value, nil
}
