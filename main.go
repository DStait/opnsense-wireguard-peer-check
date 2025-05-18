package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/tkanos/gonfig"
)

const (
	configFile string = "config.json"
)

type Config struct {
	FirewallUrl string
	ServerName  string
	Key         string
	Secret      string
}

type PeerResp struct {
	Rows     []PeerConfig `json:"rows"`
	RowCount int          `json:"rowCount"`
	Total    int          `json:"total"`
	Current  int          `json:"current"`
}

type PeerConfig struct {
	Uuid          string `json:"uuid"`
	Enabled       string `json:"enabled"`
	Name          string `json:"name"`
	Pubkey        string `json:"pubkey"`
	Psk           string `json:"psk"`
	Tunneladdress string `json:"tunneladdress"`
	Serveraddress string `json:"serveraddress"`
	Serverport    string `json:"serverport"`
	Endpoint      string `json:"endpoint"`
	Keepalive     string `json:"keepalive"`
	Servers       string `json:"servers"`
}

type ServerDetails struct {
	Rows []ServerDetail `json:"rows"`
}

type ServerDetail struct {
	Uuid string `json:"uuid"`
	Name string `json:"name"`
}

func checkErr(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func getPeers(client *http.Client, auth string, url string) string {
	const getClientsPath string = "/api/wireguard/client/searchClient"

	getClientsURL := fmt.Sprintf("%s%s", url, getClientsPath)

	req, err := http.NewRequest("GET", getClientsURL, nil)
	checkErr(err)
	// Set Authorization header
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	checkErr(err)
	defer resp.Body.Close()

	// Read the response body and convert it to string
	resBody, _ := io.ReadAll(resp.Body)
	response := string(resBody)

	return response
}

func getWantedPeers(peersString string, searchString string) []PeerConfig {
	allPeersResp := PeerResp{}
	json.Unmarshal([]byte(peersString), &allPeersResp)

	peersWanted := []PeerConfig{}
	for _, v := range allPeersResp.Rows {
		if v.Servers == searchString {
			peersWanted = append(peersWanted, v)
		}
	}

	return peersWanted
}

func isPeerUp(peer PeerConfig) bool {
	port := 443
	peerString := fmt.Sprintf("%s:%d", peer.Serveraddress, port)
	timeout := 1 * time.Second
	_, err := net.DialTimeout("tcp", peerString, timeout)
	if err != nil {
		log.Println("Site unreachable, error: ", err)
		return false
	} else {
		log.Println("Peer is available:", peer.Serveraddress)
		return true
	}
}

func setPeer(enablePeer bool, auth string, url string, peer PeerConfig, servers ServerDetails) {
	const setClientPath string = "/api/wireguard/client/setClient"

	setClientURL := fmt.Sprintf("%s%s", url, setClientPath+"/"+peer.Uuid)

	var enabled string
	if enablePeer {
		enabled = "1"
	} else {
		enabled = "0"
	}

	// When setting peer the "servers" parameter needs to be the UUID of the server
	var serversUuid string
	for _, server := range servers.Rows {
		if peer.Servers == server.Name {
			serversUuid = server.Uuid
			break
		}
	}

	type setPeerClient struct {
		Enabled       string `json:"enabled"`
		Name          string `json:"name"`
		Pubkey        string `json:"pubkey"`
		Psk           string `json:"psk"`
		Tunneladdress string `json:"tunneladdress"`
		Serveraddress string `json:"serveraddress"`
		Serverport    string `json:"serverport"`
		Servers       string `json:"servers"`
		Keepalive     string `json:"keepalive"`
	}

	settings := setPeerClient{
		Enabled:       enabled,
		Name:          peer.Name,
		Pubkey:        peer.Pubkey,
		Psk:           peer.Psk,
		Tunneladdress: peer.Tunneladdress,
		Serveraddress: peer.Serveraddress,
		Serverport:    peer.Serverport,
		Servers:       serversUuid,
		Keepalive:     peer.Keepalive,
	}

	body := struct {
		Client setPeerClient `json:"client"`
	}{
		Client: settings,
	}

	marshalledBody, err := json.Marshal(body)
	checkErr(err)

	res, code := makeRequest("POST", setClientURL, auth, bytes.NewReader(marshalledBody))

	if code != 200 {
		log.Fatal(res)
	}
}

func makeRequest(requestType string, url string, auth string, body io.Reader) ([]byte, int) {
	client := &http.Client{}
	req, err := http.NewRequest(requestType, url, body)
	checkErr(err)

	req.Header.Add("Authorization", "Basic "+auth)
	if requestType == "POST" && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	checkErr(err)
	defer resp.Body.Close()

	resBody, err := io.ReadAll(resp.Body)
	checkErr(err)

	if resp.StatusCode != 200 {
		errMessage := fmt.Sprintf(`FAIL.

	Reason: %d 
	Request Type: %s
	Request made to: %s`, resp.StatusCode, requestType, url)
		log.Fatal(errMessage)
	}
	return resBody, resp.StatusCode
}

func getServerDetails(auth string, url string) ServerDetails {
	const getServerDetailsPath string = "/api/wireguard/client/list_servers"
	getServerDetailsUrl := fmt.Sprintf("%s%s", url, getServerDetailsPath)

	serverDetailsBody, code := makeRequest("GET", getServerDetailsUrl, auth, nil)

	if code != 200 {
		log.Fatal("Error getting Server details")
	}
	serverDetailsData := ServerDetails{}
	json.Unmarshal(serverDetailsBody, &serverDetailsData)

	return serverDetailsData
}

func main() {
	// Load config
	config := Config{}
	err := gonfig.GetConf(configFile, &config)
	checkErr(err)

	fmt.Printf("Working on Firewall %s\n\n", config.FirewallUrl)

	// Peers use an id, we need to get all of these and find the ones that match our
	// criteria.

	// Encode credentials here so they can be used by all functions
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(config.Key + ":" + config.Secret))
	httpClient := &http.Client{}

	allPeers := getPeers(httpClient, encodedAuth, config.FirewallUrl)
	wantedPeers := getWantedPeers(allPeers, config.ServerName)

	// Get wireguard server details as we'll need the uuid of them when setting the peer
	serverDetails := getServerDetails(encodedAuth, config.FirewallUrl)

	// check if peer is up and enable/disable accordingly
	for _, v := range wantedPeers {
		if isPeerUp(v) {
			setPeer(true, encodedAuth, config.FirewallUrl, v, serverDetails)
		} else {
			setPeer(false, encodedAuth, config.FirewallUrl, v, serverDetails)
		}
	}

	// Apply changes
	wireguardSetUrl := "/api/wireguard/general/set"
	wireguardSetBody := []byte(`{"general": { "enabled": "1"}}`)
	makeRequest("POST", config.FirewallUrl+wireguardSetUrl, encodedAuth, bytes.NewBuffer(wireguardSetBody))

	wireguardReconfigureUrl := "/api/wireguard/service/reconfigure"
	makeRequest("POST", config.FirewallUrl+wireguardReconfigureUrl, encodedAuth, nil)
}
