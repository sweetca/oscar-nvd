package times

import (
	"strconv"
	"time"
)

const TimeLayout = "2006-01-02"

var Location, _ = time.LoadLocation("UTC")

type DateRange struct {
	From time.Time
	To   time.Time
}

func cutUnixTimeStamp(unixTimeStamp int64) string {
	unixTimeStampStringUnCut := strconv.FormatInt(unixTimeStamp, 10)
	unixTimeStampStringCut := unixTimeStampStringUnCut[:10]
	return unixTimeStampStringCut
}

func ToUtc(unixTimeStamp int64) time.Time {
	i, err := strconv.ParseInt(cutUnixTimeStamp(unixTimeStamp), 10, 64)
	if err != nil {
		panic(err)
	}
	unixTime := time.Unix(i, 0).In(Location)
	timeUnixString := unixTime.Format(TimeLayout)

	timeParsed, _ := time.ParseInLocation(TimeLayout, timeUnixString, Location)
	timeParsedString := timeParsed.Format(TimeLayout)
	timeParsed, _ = time.ParseInLocation(TimeLayout, timeParsedString, Location)
	return timeParsed.UTC()
}

func TimeFromString(timeToParse string) time.Time {
	result, err := time.ParseInLocation(TimeLayout, timeToParse, Location)
	if err != nil {
		panic(err)
	}
	return result.UTC()
}

func RoundDate(timeToRound time.Time) time.Time {
	return time.Date(timeToRound.Year(), timeToRound.Month(), timeToRound.Day(), 0, 0, 0, 0, time.UTC)
}

func LastTimeSeriesDate() time.Time {
	return time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
}

func Date(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// setting timezone to UTC
func SetUTC() {
	var location, _ = time.LoadLocation("UTC")
	time.Local = location
}
