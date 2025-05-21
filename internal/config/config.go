package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	AI      AIConfig      `yaml:"ai"`
	Storage StorageConfig `yaml:"storage"`
	Log     LogConfig     `yaml:"log"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
	Mode string `yaml:"mode"`
}

type AIConfig struct {
	ModelPath string  `yaml:"model_path"`
	Threshold float32 `yaml:"threshold"`
	BatchSize int     `yaml:"batch_size"`
}

type StorageConfig struct {
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch"`
	Redis         RedisConfig         `yaml:"redis"`
	Neo4j         Neo4jConfig         `yaml:"neo4j"`
}

type ElasticsearchConfig struct {
	Hosts       []string `yaml:"hosts"`
	IndexPrefix string   `yaml:"index_prefix"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type Neo4jConfig struct {
	URI      string `yaml:"uri"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
