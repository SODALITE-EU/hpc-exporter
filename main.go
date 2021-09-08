package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	log "github.com/sirupsen/logrus"

	"hpc_exporter/api"
	"hpc_exporter/conf"

	"github.com/gorilla/mux"
)

var (
	addr = flag.String(
		"listen-address",
		":9110",
		"The address to listen on for HTTP requests.",
	)

	logLevel = flag.String(
		"log-level",
		"error",
		"Log level of the Application.",
	)

	introspection_endpoint = flag.String(
		"introspection-endpoint",
		"",
		"Introspection endpoint to check JWT (Keycloak).",
	)

	introspection_client = flag.String(
		"introspection-client",
		"",
		"Introspection client.",
	)

	introspection_secret = flag.String(
		"introspection-secret",
		"",
		"Introspection client secret.",
	)

	vault_secret_uploader_address = flag.String(
		"vault-secret-uploader-address",
		"",
		"Vault login endpoint.",
	)
)

func main() {
	flag.Parse()
	// Parse and set log lovel
	level, err := log.ParseLevel(*logLevel)
	if err == nil {
		log.SetLevel(level)
	} else {
		log.SetLevel(log.WarnLevel)
		log.Warnf("Log level %s not recognized, setting 'warn' as default.")
	}

	security_config := conf.NewSecurityConf()

	if *introspection_endpoint == "" {
		security_config.Introspection_endpoint = os.Getenv("OIDC_INTROSPECTION_ENDPOINT")
		if len(security_config.Introspection_endpoint) == 0 {
			log.Fatal("No introspection endpoint given. Provide argument --introspection-endpoint or set environment variable OIDC_INTROSPECTION_ENDPOINT")
		}
	} else {
		security_config.Introspection_endpoint = *introspection_endpoint
	}

	if *introspection_client == "" {
		security_config.Introspection_client = os.Getenv("OIDC_INTROSPECTION_CLIENT")
		if len(security_config.Introspection_client) == 0 {
			security_config.Introspection_client = "sodalite-ide"
		}
	} else {
		security_config.Introspection_client = *introspection_client
	}

	if *introspection_secret == "" {
		security_config.Introspection_secret = os.Getenv("OIDC_CLIENT_SECRET")
		if len(security_config.Introspection_secret) == 0 {
			log.Fatal("No introspection secret given. Provide argument --introspection-secret or set environment variable OIDC_CLIENT_SECRET")
		}
	} else {
		security_config.Introspection_secret = *introspection_secret
	}

	if *vault_secret_uploader_address == "" {
		security_config.Vault_secret_uploader_address = os.Getenv("VAULT_SECRET_UPLOADER_ADDRESS")
		if len(security_config.Vault_secret_uploader_address) == 0 {
			log.Fatal("No vault-secret-uploader address given. Provide argument --vault-secret-uploader-address or set environment variable VAULT_SECRET_UPLOADER_ADDRESS")
		}
	} else {
		security_config.Vault_secret_uploader_address = *vault_secret_uploader_address
	}

	collectorStore := api.NewCollectorStore(security_config)
	// Expose the registered metrics via HTTP.
	log.Infof("Starting Server: %s", *addr)

	router := mux.NewRouter()
	router.Handle("/metrics", promhttp.Handler())
	router.HandleFunc("/collector", collectorStore.CreateHandler).Methods("POST")
	router.HandleFunc("/collector", collectorStore.DeleteHandler).Methods("DELETE")
	router.HandleFunc("/job", collectorStore.AddJobHandler).Methods("POST")
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Multi-Tenant HPC Exporter</title></head>
			<body>
			<h1>HPC Exporter</h1>
			<p><a href="/metrics">Metrics</a></p>
			</body>
			</html>`))
	}).Methods("GET")
	log.Debug(http.ListenAndServe(*addr, router))
}
