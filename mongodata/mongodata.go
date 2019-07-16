package mongodata

import (
	"context"
	"github.com/codescoop/oscar-nvd/models"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

const TableVulnerability = "vulnerability"

var config Config

type Config struct {
	Url      string
	Auth     bool
	Login    string
	Password string
	Db       string
}

func Setup(cnfg Config) {
	config = cnfg
}

func GetConfig() Config {
	return config
}

func InitClient(ctx context.Context) *mongo.Client {
	url := "mongodb://"
	if config.Auth {
		url = url + config.Login + ":" + config.Password + "@"
	}
	url = url + config.Url + "/" + config.Db + "?authMechanism=SCRAM-SHA-1"

	opts := options.Client()
	timeout := time.Minute * 15
	opts.ServerSelectionTimeout = &timeout

	client, err := mongo.NewClient(opts.ApplyURI(url))
	if err != nil {
		log.Panicf("Error MongoDb client init : %v", err)
	}

	err = client.Connect(ctx)
	if err != nil {
		log.Panicf("Error MongoDb connection : %v", err)
	}

	return client
}

func WriteCVE(client *mongo.Client, ctx context.Context, cveFeed []models.CVE) {
	updates := make([]mongo.WriteModel, 0)
	for _, cve := range cveFeed {
		if len(cve.Id) == 0 {
			log.Error("empty cve")
			continue
		}
		updateModel := mongo.NewUpdateOneModel().
			SetFilter(bson.M{"cveId": cve.Id}).
			SetUpdate(bson.M{"$set": cve}).
			SetUpsert(true)
		updates = append(updates, updateModel)
	}

	result, err := client.
		Database(config.Db).
		Collection(TableVulnerability).
		BulkWrite(ctx, updates)

	if err != nil {
		log.Panicf("save vulnerabilities : %v", err)
	}
	log.Debugf("save vulnerabilities : modified - %v, upserted - %v", result.ModifiedCount, result.UpsertedCount)
}
