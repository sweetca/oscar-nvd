package models

import "time"

type Job struct {
	Id       string `json:"id"`
	Finished bool   `json:"finished"`
	Locked   bool   `json:"locked"`
	Type     int32  `json:"type"`
}

type CVEMeta struct {
	Cpe        []string      `bson:"cpe"`
	Affects    []string      `bson:"affects"`
	Ref        []string      `bson:"references"`
	Categories []CVECategory `bson:"categories"`
	Published  time.Time     `bson:"published"`
	Modified   time.Time     `bson:"modified"`
	Severity   float64       `bson:"severity"`
}

type CVECategory struct {
	Name        string `json:"name" bson:"name"`
	Id          string `json:"id" bson:"id"`
	Description string `json:"description" bson:"description"`
}

// Common Vulnerabilities and Exposures
type CVE struct {
	Id   string                 `bson:"cveId"`
	Data map[string]interface{} `bson:"data"`
	Meta *CVEMeta               `bson:"meta"`
}
