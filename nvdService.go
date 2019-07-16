package main

import (
	"flag"
	"github.com/codescoop/oscar-nvd/executor"
	"github.com/codescoop/oscar-nvd/profile"
	log "github.com/sirupsen/logrus"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"
)

var profileSetup = flag.String("profile", "local", "profile settings file")

var processing = false

func main() {
	flag.Parse()
	profile.InitProfile(*profileSetup)

	log.Warn("NVD crawler is running")

	http.HandleFunc("/", handleHealth)

	go func() {
		time.Sleep(5 * time.Second)
		charge()
	}()

	err := http.ListenAndServe(profile.PortBasic, nil)
	if err != nil {
		log.Panicf("ERROR: NVD is fall down : %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

func charge() {
	if !processing {
		processing = true
		go func(processing *bool) {
			result := executor.Run()
			if result {
				log.Info("NVD task processed")
			}
			runtime.GC()
			debug.FreeOSMemory()

			*processing = false
		}(&processing)
	}
}
