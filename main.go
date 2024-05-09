package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/spf13/viper"
)

var (
	logger         *slog.Logger
	debugLogger    *slog.Logger
	configFileName string
	config         *ConfigType
	esClient       *elasticsearch.Client
	event          = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "webhook_event",
		Help: "The amount of requests to an endpoint",
	}, []string{"event", "status"},
	)
)

const (
	BaseENVname = "HOOK"
	webhookPath = "/webhook"
)

type ConfigType struct {
	Logging    ConfigLogging    `mapstructure:"logging"`
	Port       string           `mapstructure:"port"`
	Prometheus ConfigPrometheus `mapstructure:"prometheus"`
	Elastic    ConfigElastic    `mapstructure:"elastic"`
	Github     ConfigGithub     `mapstructure:"github"`
}
type ConfigLogging struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}
type ConfigPrometheus struct {
	Enabled  bool   `mapstructure:"enabled"`
	Endpoint string `mapstructure:"endpoint"`
}
type ConfigGithub struct {
	Secret   string `mapstructure:"secret"`
	Endpoint string `mapstructure:"endpoint"`
}
type ConfigElastic struct {
	Addresses         []string `mapstructure:"addresses"`
	Username          string   `mapstructure:"username"`
	Password          string   `mapstructure:"password"`
	CACert            string   `mapstructure:"cacert"`
	EnableMetrics     bool     `mapstructure:"enableMetrics"`
	EnableDebugLogger bool     `mapstructure:"enableDebugLogging"`
	Index             string   `mapstructure:"index"`
}

func (cfg *ConfigElastic) getConfig() *elasticsearch.Config {
	debugLogger.Debug("reading Elatic search config")
	config := &elasticsearch.Config{
		Addresses:         cfg.Addresses,
		Username:          cfg.Username,
		Password:          cfg.Password,
		EnableMetrics:     cfg.EnableMetrics,
		EnableDebugLogger: cfg.EnableDebugLogger,
	}
	if cfg.CACert != "" {
		sDec, err := base64.StdEncoding.DecodeString(cfg.CACert)
		if err != nil {
			logger.Error("error decoding base64", "error", err)
			os.Exit(1)
		}
		config.CACert = sDec
	}
	return config
}

func ConfigRead(configFileName string, configOutput *ConfigType) *viper.Viper {
	configReader := viper.New()
	configReader.SetConfigName(configFileName)
	configReader.SetConfigType("yaml")
	configReader.AddConfigPath("/app/")
	configReader.AddConfigPath(".")
	configReader.SetEnvPrefix(BaseENVname)
	configReader.SetDefault("logging.level", "Debug")
	configReader.SetDefault("logging.format", "text")
	configReader.SetDefault("port", 8080)
	configReader.SetDefault("prometheus.enabled", true)
	configReader.SetDefault("prometheus.endpoint", "/metrics")
	configReader.SetDefault("elastic.addresses", []string{"https://elastic.tpi.stiil.dk:443"})
	configReader.SetDefault("elastic.username", "github-hook")
	configReader.SetDefault("elastic.password", "testpassword")
	configReader.SetDefault("elastic.enableMetrics", true)
	configReader.SetDefault("elastic.enableDebugLogging", true)
	configReader.SetDefault("elastic.index", "application-github-webhook-test")
	configReader.SetDefault("github.secret", "application-github-webhook-test")
	configReader.SetDefault("github.endpoint", "/webhook")
	//configReader.SetDefault("elastic.cacert", "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGYXpDQ0ExT2dBd0lCQWdJUkFJSVF6N0RTUU9OWlJHUGd1Mk9DaXdBd0RRWUpLb1pJaHZjTkFRRUxCUUF3DQpUekVMTUFrR0ExVUVCaE1DVlZNeEtUQW5CZ05WQkFvVElFbHVkR1Z5Ym1WMElGTmxZM1Z5YVhSNUlGSmxjMlZoDQpjbU5vSUVkeWIzVndNUlV3RXdZRFZRUURFd3hKVTFKSElGSnZiM1FnV0RFd0hoY05NVFV3TmpBME1URXdORE00DQpXaGNOTXpVd05qQTBNVEV3TkRNNFdqQlBNUXN3Q1FZRFZRUUdFd0pWVXpFcE1DY0dBMVVFQ2hNZ1NXNTBaWEp1DQpaWFFnVTJWamRYSnBkSGtnVW1WelpXRnlZMmdnUjNKdmRYQXhGVEFUQmdOVkJBTVRERWxUVWtjZ1VtOXZkQ0JZDQpNVENDQWlJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dJUEFEQ0NBZ29DZ2dJQkFLM29KSFAwRkRmem01NHJWeWdjDQpoNzdjdDk4NGtJeHVQT1pYb0hqM2RjS2kvdlZxYnZZQVR5amIzbWlHYkVTVHRyRmovUlFTYTc4ZjB1b3hteUYrDQowVE04dWtqMTNYbmZzN2ovRXZFaG1rdkJpb1p4YVVwbVpteVBmanh3djYwcElnYno1TURtZ0s3aVM0KzNtWDZVDQpBNS9UUjVkOG1VZ2pVK2c0cms4S2I0TXUwVWxYaklCMHR0b3YwRGlOZXdOd0lSdDE4akE4K28rdTNkcGpxK3NXDQpUOEtPRVV0K3p3dm8vN1YzTHZTeWUwcmdUQklsREhDTkF5bWc0Vk1rN0JQWjdobS9FTE5LakQrSm8yRlIzcXlIDQpCNVQwWTNIc0x1SnZXNWlCNFlsY05IbHNkdTg3a0dKNTV0dWttaThteGRBUTRRN2UyUkNPRnZ1Mzk2ajN4K1VDDQpCNWlQTmdpVjUrSTNsZzAyZFo3N0RuS3hIWnU4QS9sSkJkaUIzUVcwS3RaQjZhd0JkcFVLRDlqZjFiMFNIelV2DQpLQmRzMHBqQnFBbGtkMjVITjdyT3JGbGVhSjEvY3RhSnhRWkJLVDVaUHQwbTlTVEpFYWRhbzB4QUgwYWhtYlduDQpPbEZ1aGp1ZWZYS25FZ1Y0V2UwK1VYZ1ZDd09QamRBdkJiSStlMG9jUzNNRkV2ekc2dUJRRTN4RGszU3p5blRuDQpqaDhCQ05BdzFGdHhOclFIdXNFd01GeEl0NEk3bUtaOVlJcWlveW1DekxxOWd3UWJvb01EUWFIV0JmRWJ3cmJ3DQpxSHlHTzBhb1NDcUkzSGFhZHI4ZmFxVTlHWS9yT1BOazNzZ3JEUW9vLy9mYjRoVkMxQ0xRSjEzaGVmNFk1M0NJDQpyVTdtMllzNnh0MG5VVzcvdkdUMU0wTlBBZ01CQUFHalFqQkFNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVBCZ05WDQpIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJSNXRGbm1lN2JsNUFGemdBaUl5QnBZOXVtYmJqQU5CZ2txDQpoa2lHOXcwQkFRc0ZBQU9DQWdFQVZSOVlxYnl5cUZEUURMSFlHbWtnSnlrSXJHRjFYSXB1K0lMbGFTL1Y5bFpMDQp1Ymh6RUZuVElaZCs1MHh4KzdMU1lLMDVxQXZxRnlGV2hmRlFEbG5yenVCWjZickpGZStHblkrRWdQYms2WkdRDQozQmViWWh0RjhHYVYwbnh2d3VvNzd4L1B5OWF1Si9HcHNNaXUvWDErbXZvaUJPdi8yWC9xa1NzaXNSY09qL0tLDQpORnRZMlB3QnlWUzV1Q2JNaW9nemlVd3RoRHlDMys2V1Z3VzZMTHYzeExmSFRqdUN2akhJSW5Oemt0SENnS1E1DQpPUkF6STRKTVBKK0dzbFdZSGI0cGhvd2ltNTdpYXp0WE9vSndUZHdKeDRuTENnZE5iT2hkanNudnpxdkh1N1VyDQpUa1hXU3RBbXpPVnl5Z2hxcFpYakZhSDNwTzNKTEYrbCsvK3NLQUl1dnRkN3UrTnhlNUFXMHdkZVJsTjhOd2RDDQpqTlBFbHB6Vm1iVXE0SlVhZ0VpdVREa0h6c3hIcEZLVks3cTQrNjNTTTFOOTVSMU5iZFdoc2NkQ2IrWkFKelZjDQpveWkzQjQzbmpUT1E1eU9mKzFDY2VXeEcxYlFWczVadWZwc01sanE0VWkwLzFsdmgrd2pDaFA0a3FLT0oycXhxDQo0Umdxc2FoRFlWdlRIOXc3alhieUxlaU5kZDhYTTJ3OVUvdDd5MEZmLzl5aTBHRTQ0WmE0ckYyTE45ZDExVFBBDQptUkd1blVIQmNuV0V2Z0pCUWw5bkpFaVUwWnNudmdjL3ViaFBnWFJSNFhxMzdaMGo0cjdnMVNnRUV6d3hBNTdkDQplbXlQeGdjWXhuL2VSNDQvS0o0RUJzK2xWRFIzdmV5Sm0ra1hROTliMjEvK2poNVhvczFBblg1aUl0cmVHQ2M9DQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tDQo=")

	err := configReader.ReadInConfig() // Find and read the config file
	if err != nil {                    // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	configReader.AutomaticEnv()
	configReader.Unmarshal(configOutput)
	return configReader
}
func setupLogging(Logging ConfigLogging) {
	logLevel := strings.ToLower(Logging.Level)
	logFormat := strings.ToLower(Logging.Format)
	loggingLevel := new(slog.LevelVar)
	switch logLevel {
	case "debug":
		loggingLevel.Set(slog.LevelDebug)
	case "warn":
		loggingLevel.Set(slog.LevelWarn)
	case "error":
		loggingLevel.Set(slog.LevelError)
	default:
		loggingLevel.Set(slog.LevelInfo)
	}

	output := os.Stdout
	switch logFormat {
	case "json":
		logger = slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: loggingLevel}))
		debugLogger = slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: loggingLevel, AddSource: true}))
	default:
		logger = slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{Level: loggingLevel}))
		debugLogger = slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{Level: loggingLevel, AddSource: true}))
	}
	logger.Info("Logging started with options", "format", Logging.Format, "level", Logging.Level, "function", "setupLogging")
	slog.SetDefault(logger)
}

func main() {
	var err error
	flag.StringVar(&configFileName, "config", "config", "Use a different config file name")
	flag.Parse()
	config = new(ConfigType)
	ConfigRead(configFileName, config)
	setupLogging(config.Logging)
	esClient, err = elasticsearch.NewClient(*config.Elastic.getConfig())
	if err != nil {
		logger.Error("error staring elasticsearch client", "error", err)
		os.Exit(1)
	}
	// Mapping file created based on https://json-to-es-mapping.netlify.app/ sourounded by "mappings": {}
	mappingFile, err := os.Open("mapping.json")
	if err != nil {
		logger.Error("error opening mappings file", "error", err)
		os.Exit(2)
	}
	res, err := esClient.Indices.Exists([]string{config.Elastic.Index})
	if err != nil {
		logger.Error("error creating indice", "error", err)
	}
	if res.StatusCode == http.StatusNotFound {
		logger.Info("Indice does not exist, creating it")
		res, err := esClient.Indices.Create(config.Elastic.Index, esClient.Indices.Create.WithBody(mappingFile))
		if err != nil {
			logger.Error("error creating indice", "error", err)
		}
		if res.IsError() {
			printESError("error result creating indice", res)
		}
	} else {
		if res.StatusCode == http.StatusOK {
			logger.Info("Indice already exists")
		} else {
			logger.Error("Unknown response", "response", res)
		}
	}
	hook := &Webhook{secret: config.Github.Secret}
	if err != nil {
		logger.Error("error creating github hook", "error", err)
	}
	http.HandleFunc(config.Github.Endpoint, func(w http.ResponseWriter, r *http.Request) {
		gitEvent := r.Header.Get("X-GitHub-Event")
		payload, err := hook.Parse(r)
		if err != nil {
			if err == ErrEventNotFound || err == ErrEventNotSpecifiedToParse {
				debugLogger.Debug("unwanted github event", "error", err)
				event.WithLabelValues(gitEvent, "Skipped").Inc()
			} else {
				logger.Warn("error parsing github event", "error", err)
				event.WithLabelValues(gitEvent, "ParseErr").Inc()
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
		} else {
			id := r.Header.Get("X-GitHub-Delivery")
			debugLogger.Debug("Handleing pull request", "id", id, "repository", payload.PullRequest.Head.Repo.FullName, "action", payload.Action, "number", payload.Number)
			byteArray, err := payload.parse()
			if err != nil {
				event.WithLabelValues(gitEvent, "IntErr").Inc()
				logger.Error("error parsing payload to json", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
			debugLogger.Debug("payload", "data", string(byteArray))
			ctx := context.Background()
			res, err := esapi.CreateRequest{
				Index:      config.Elastic.Index,
				DocumentID: id,
				Body:       bytes.NewReader(byteArray),
			}.Do(ctx, esClient)
			if err != nil {
				event.WithLabelValues(gitEvent, "ESConErr").Inc()
				logger.Error("error parsing payload to json", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
			if res.IsError() {
				event.WithLabelValues(gitEvent, "ESIntErr").Inc()
				printESError("error posting value", res)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
			event.WithLabelValues(gitEvent, "OK").Inc()
		}
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{\"Status\": \"UP\"}"))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Webhook Server go to /webhook"))
	})
	if config.Prometheus.Enabled {
		http.Handle(config.Prometheus.Endpoint, promhttp.Handler())
	}
	http.ListenAndServe(fmt.Sprintf(":%v", config.Port), nil)
}
func printESError(message string, res *esapi.Response) {
	bodyText, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Error("error reading body", "error", err)
	}
	var e map[string]interface{}
	err = json.Unmarshal(bodyText, &e)
	if err != nil {
		logger.Error("error unmarshaling body", "body", bodyText, "error", err)
	}
	logger.Error(message, "status", res.Status(), "type", e["error"].(map[string]interface{})["type"], "reason", e["error"].(map[string]interface{})["reason"])
}
