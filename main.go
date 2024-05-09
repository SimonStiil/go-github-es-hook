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
	if cfg.Password == "" {
		debugLogger.Debug("Password empty?")
	}
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
	configReader.SetDefault("elastic.addresses", []string{"http://localhost:9200"})
	configReader.SetDefault("elastic.username", "github-hook")
	configReader.SetDefault("elastic.enableMetrics", true)
	configReader.SetDefault("elastic.enableDebugLogging", true)
	configReader.SetDefault("elastic.index", "application-github-webhook-test")
	configReader.SetDefault("github.secret", "application-github-webhook-test")
	configReader.SetDefault("github.endpoint", "/webhook")

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
	envPassword := os.Getenv(BaseENVname + "_ELASTIC_PASSWORD")
	if envPassword != "" {
		config.Elastic.Password = envPassword
	}
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
			if res.StatusCode == http.StatusUnauthorized {
				logger.Error("Elastic Connection Unauthorized", "response", res)
				os.Exit(-1)
			} else {
				logger.Error("Unknown response", "response", res)
			}
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
				debugLogger.Debug("unwanted github event", "event", gitEvent, "error", err)
				event.WithLabelValues(gitEvent, "Skipped").Inc()
			} else {
				logger.Warn("error parsing github event", "event", gitEvent, "error", err)
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
	portString := fmt.Sprintf(":%v", config.Port)
	logger.Info("listeining on port " + portString)
	http.ListenAndServe(portString, nil)
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
