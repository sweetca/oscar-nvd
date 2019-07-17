package profile

import (
	"github.com/codescoop/oscar-nvd/mongodata"
	"github.com/codescoop/oscar-nvd/times"
	"github.com/codescoop/oscar-nvd/util"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
)

var OssApiJob = "JOB_MODULE_HOST"
var PortBasic = ":8084"
var MongoUrl = "MONGO_HOST"
var MongoDb = "DB"
var MongoAuth = true
var MongoLogin = "MONGO_LOGIN"
var MongoPass = "MONGO_PASSWORD"
var CronExpression = "0 */1 * * * ?"

var Profile *Config
var ThreadPoolSize = runtime.GOMAXPROCS(0)

var profilePath = "./profile/"

func InitProfile(profileName string) {
	times.SetUTC()
	if Profile == nil {
		if profileName == "local" || profileName == "test" {
			log.SetLevel(log.DebugLevel)
			CronExpression = "*/5 * * * * ?"
		} else {
			log.SetLevel(log.InfoLevel)
		}

		fullPath := profilePath + profileName + ".yml"
		filename, errProfile := filepath.Abs(fullPath)
		if errProfile != nil {
			log.Panicf("Error getting absolute path to profile : %v", errProfile)
		}
		log.Infof("profile abs path: %v", filename)

		yamlFile, err := ioutil.ReadFile(filename)
		err = yaml.Unmarshal(yamlFile, &Profile)
		if err != nil {
			log.Panicf("error marshaling profile : %v", err)
		}

		// Google cloud Access

		PortBasic = Profile.PortBasic
		OssApiJob = Profile.ApiJobUrl

		MongoUrl = Profile.MongoUrl
		MongoDb = Profile.MongoDb
		MongoAuth = Profile.MongoAuth
		MongoLogin = Profile.MongoLogin
		MongoPass = os.Getenv("MONGO_PASS")
		if MongoPass == "" {
			MongoPass = Profile.MongoPass
		}

		mongodata.Setup(mongodata.Config{
			Auth:     MongoAuth,
			Login:    MongoLogin,
			Password: MongoPass,
			Url:      MongoUrl,
			Db:       MongoDb})

		util.Setup(util.Config{
			ApiJob:  OssApiJob,
			PodName: "oscar-nvd-1",
			Profile: profileName,
			JobType: "41"})
	}
}

type Config struct {
	PortBasic  string `yaml:"port_basic"`
	ApiJobUrl  string `yaml:"api_job_url"`
	MongoUrl   string `yaml:"mongo_url"`
	MongoDb    string `yaml:"mongo_db"`
	MongoAuth  bool   `yaml:"mongo_auth"`
	MongoLogin string `yaml:"mongo_login"`
	MongoPass  string `yaml:"mongo_pass"`
}
