package util

import (
	"encoding/json"
	"fmt"
	"github.com/codescoop/oscar-nvd/models"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

var config Config

type Config struct {
	ApiJob  string
	PodName string
	Profile string
	JobType string
}

func Setup(cnfg Config) {
	config = cnfg
}

func FetchJob() (job *models.Job) {
	if len(config.PodName) == 0 {
		log.Panicf("Pod name is not defined!")
	}

	client := &http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/find_job/%s/%s",
		config.ApiJob, config.JobType, config.PodName), nil)
	req.Header.Set("Accept", "application/json")

	response, err := client.Do(req)
	if err != nil {
		log.Warn(err)
		return
	}
	if response.StatusCode != 200 {
		log.Infof("No new job of type %s for pod %s", config.JobType, config.PodName)
		return
	}

	defer response.Body.Close()
	job = new(models.Job)
	bodyString, _ := ioutil.ReadAll(response.Body)
	s := string(bodyString)
	err = json.Unmarshal([]byte(s), job)
	if err != nil {
		log.Panicf("ERROR: unmarshal job : %v", err)
	}
	return
}

func FinishJob(job models.Job) (err error) {
	client := &http.Client{}
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/finish_job/%s/%s", config.ApiJob, job.Id, config.PodName), nil)
	req.Header.Set("Accept", "application/json")

	_, err = client.Do(req)
	if err != nil {
		log.Panicf("ERROR: finish job : %v : %v", job.Id, err)
	}
	return
}