package main

import (
	"flag"
	"io/ioutil"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	log "github.com/sirupsen/logrus"

	"hpc_exporter/pbs"
	"hpc_exporter/slurm"
)

var (
	addr = flag.String(
		"listen-address",
		":9110",
		"The address to listen on for HTTP requests.",
	)

	scheduler = flag.String(
		"scheduler",
		"pbs",
		"Type of scheduler",
	)

	host = flag.String(
		"host",
		"localhost",
		"HPC infrastructure domain name or IP.",
	)

	sshUser = flag.String(
		"ssh-user",
		"",
		"SSH user for remote frontend connection (no localhost).",
	)

	sshAuthMethod = flag.String(
		"ssh-auth-method",
		"keypair",
		"SSH authentication method for remote frontend connection (no localhost). keypair, keypair-file, password",
	)

	sshPass = flag.String(
		"ssh-password",
		"",
		"SSH password for remote frontend connection (no localhost).",
	)

	sshPrivKey = flag.String(
		"ssh-priv-key",
		"",
		"SSH private key recognised by the remote frontend",
	)

	sshPrivKeyFile = flag.String(
		"ssh-priv-key-file",
		"",
		"Path to the SSH private key recognised by the remote frontend",
	)

	sshKnownHosts = flag.String(
		"ssh-known-hosts",
		"",
		"Path to the SSH local known_hosts file including the remote frontend",
	)

	sacctHistory = flag.Int(
		"sacct-history",
		5,
		"If no target JobIds are given, jobs reported will be the ones submitted this many days back. Default is 5. Only applicable to Slurm",
	)

	scrapeInterval = flag.Int(
		"scrape-interval",
		300,
		"How often (in seconds) SSH commands will be executed on the HPC frontend to update metrics",
	)

	logLevel = flag.String(
		"log-level",
		"error",
		"Log level of the Application.",
	)

	targetJobIds = flag.String(
		"job-ids",
		"",
		"Comma-separated ids of the specific HPC jobs to monitor. Keep it unset to monitor all the user's jobs.",
	)

	targetJobsFile = flag.String(
		"job-file",
		"",
		"Path where the jobIds to monitor are stored. Used to dynamically change them. If it is not used, no dynamic monitoring of jobs will be performed",
	)

	deploymentLabel = flag.String(
		"deployment-label",
		"no_label",
		"Deployment label of which the exporter is a part of.",
	)

	hpcLabel = flag.String(
		"hpc-label",
		"no_label",
		"Name of the HPC. Will be the value on the hpc label on all metrics",
	)

	deploymentID = flag.String(
		"deployment-id",
		"no_label",
		"Deployment id of which the exporter is a part of.",
	)

	skipInfra = flag.Bool(
		"only-jobs",
		false,
		"Skip queue or partition metrics. False by default",
	)
)

func main() {
	flag.Parse()
	var key []byte
	// Parse and set log lovel
	level, err := log.ParseLevel(*logLevel)
	if err == nil {
		log.SetLevel(level)
	} else {
		log.SetLevel(log.WarnLevel)
		log.Warnf("Log level %s not recognized, setting 'warn' as default.")
	}

	// Flags check
	if *host == "localhost" {
		flag.Usage()
		log.Fatalln("Localhost connection not implemented yet.")
	} else {
		if *sshUser == "" {
			flag.Usage()
			log.Fatalln("A user must be provided to connect to a frontend remotely.")
		}
		switch authmethod := *sshAuthMethod; authmethod {
		case "keypair-file":
			//				if (*sshPrivKey == "" || *sshKnownHosts == "") {
			if *sshPrivKeyFile == "" {
				flag.Usage()
				//					log.Fatalln("Paths to a private key and a known hosts file should be provided to connect to a frontend remotely using this authentication method.")
				log.Fatalln("Path to a private key file should be provided to connect to a frontend remotely using this authentication method.")
			}
			if *sshKnownHosts == "" {
				log.Infoln("Known hosts file is not mandatory but recommended.")
			}
			key, err = ioutil.ReadFile(*sshPrivKeyFile)
			if err != nil {
				log.Fatalf("unable to read private key file: %v", err)
			} else {
				log.Info("Local private key file read")
				*sshAuthMethod = "keypair"
			}
		case "keypair":
			//				if (*sshPrivKey == "" || *sshKnownHosts == "") {
			if *sshPrivKey == "" {
				flag.Usage()
				//					log.Fatalln("Paths to a private key and a known hosts file should be provided to connect to a frontend remotely using this authentication method.")
				log.Fatalln("Private key should be provided to connect to a frontend remotely using this authentication method.")
			}
			if *sshKnownHosts == "" {
				log.Infoln("Known hosts file is not mandatory but recommended.")
			}

			key = []byte(*sshPrivKey)
		case "password":
			if *sshPass == "" {
				flag.Usage()
				log.Fatalln("A password should be provided to connect to a frontend remotely using this authentication method.")
			}
		default:
			flag.Usage()
			log.Fatalf("The authentication method provided (%s) is not supported.", authmethod)
		}
	}
	constLabels := make(prometheus.Labels)
	constLabels["deployment_label"] = *deploymentLabel
	constLabels["hpc"] = *hpcLabel
	constLabels["deployment_id"] = *deploymentID

	switch sched := *scheduler; sched {
	case "pbs":
		log.Debugf("Registering collector for scheduler %s", sched)
		prometheus.MustRegister(pbs.NewerPBSCollector(*host, *sshUser, *sshAuthMethod, *sshPass, key, *sshKnownHosts, "", *scrapeInterval, *targetJobIds, *targetJobsFile, constLabels, *skipInfra))
	case "slurm":
		log.Debugf("Registering collector for scheduler %s", sched)
		prometheus.MustRegister(slurm.NewerSlurmCollector(*host, *sshUser, *sshAuthMethod, *sshPass, key, *sshKnownHosts, "", *sacctHistory, *scrapeInterval, *targetJobIds, *targetJobsFile, constLabels, *skipInfra))
	default:
		log.Fatalf("The scheduler type provided (%s) is not supported.", sched)
	}

	// Expose the registered metrics via HTTP.
	log.Infof("Starting Server: %s", *addr)
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(*addr, nil))
}
