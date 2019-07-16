package client

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
)

const (
	URLFeed         = "https://nvd.nist.gov/feeds/json/cve/1.0/"
	CVENameTemplate = "nvdcve-1.0-%s.json.gz"
)

const (
	FirstYear  = 2002
	LastYear   = 2019
	Recent     = "recent"
	Modidified = "modified"
)

type NVDClient struct {
	client *http.Client
}

func New() *NVDClient {
	return &NVDClient{
		client: &http.Client{},
	}
}

func (c *NVDClient) FetchCVEFeed(spec string) map[string]interface{} {
	fileName := fmt.Sprintf(CVENameTemplate, spec)
	url := URLFeed + fileName
	resp := c.makeRequest(url)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Panicf("nvd client reading data from stream error : %v : %v", spec, err)
	}
	var zipBuf bytes.Buffer
	zipBuf.Write(body)
	zipReader, err := gzip.NewReader(&zipBuf)
	if err != nil {
		log.Panicf("nvd client unzip data from buffer error : %v : %v", spec, err)
	}
	var byteBuf bytes.Buffer
	if _, err := io.Copy(&byteBuf, zipReader); err != nil {
		log.Panicf("nvd client fetching data from buffer error : %v : %v", spec, err)
	}
	if err := zipReader.Close(); err != nil {
		log.Panicf("nvd client reader close error : %v : %v", spec, err)
	}

	cveFeed := new(map[string]interface{})
	if err := json.Unmarshal(byteBuf.Bytes(), cveFeed); err != nil {
		log.Panicf("nvd client unmarshal data from buffer error : %v : %v", spec, err)
	}
	_ = resp.Body.Close()
	return *cveFeed
}

func (c *NVDClient) makeRequest(url string) *http.Response {
	log.Debugf("REQ %s", url)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		panic(err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		panic(err)
	}
	return resp
}
