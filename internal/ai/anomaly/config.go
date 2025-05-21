package anomaly

// ModelConfig defines the configuration for anomaly detection model
type ModelConfig struct {
	// Model architecture parameters
	InputDim      int     `json:"input_dim"      yaml:"input_dim"`
	HiddenDim     int     `json:"hidden_dim"     yaml:"hidden_dim"`
	NumLayers     int     `json:"num_layers"     yaml:"num_layers"`
	DropoutRate   float32 `json:"dropout_rate"   yaml:"dropout_rate"`

	// Training parameters
	BatchSize     int     `json:"batch_size"     yaml:"batch_size"`
	LearningRate  float32 `json:"learning_rate"  yaml:"learning_rate"`
	NumEpochs     int     `json:"num_epochs"     yaml:"num_epochs"`

	// Anomaly detection parameters
	Threshold     float32 `json:"threshold"      yaml:"threshold"`
	WindowSize    int     `json:"window_size"    yaml:"window_size"`
	FeatureNames  []string `json:"feature_names" yaml:"feature_names"`

	// Model optimization
	EarlyStopPatience int  `json:"early_stop_patience" yaml:"early_stop_patience"`
	UseGPU           bool `json:"use_gpu"            yaml:"use_gpu"`

	// Feature engineering
	FeatureNormalization bool    `json:"feature_normalization" yaml:"feature_normalization"`
	OutlierRemoval      bool    `json:"outlier_removal"       yaml:"outlier_removal"`
	OutlierThreshold    float32 `json:"outlier_threshold"     yaml:"outlier_threshold"`
}

// NewDefaultConfig returns a default model configuration
func NewDefaultConfig() *ModelConfig {
	return &ModelConfig{
		// Model architecture
		InputDim:    128,
		HiddenDim:   64,
		NumLayers:   2,
		DropoutRate: 0.2,

		// Training parameters
		BatchSize:    32,
		LearningRate: 0.001,
		NumEpochs:    100,

		// Anomaly detection
		Threshold:  0.95,
		WindowSize: 10,
		FeatureNames: []string{
			"timestamp", "source_ip", "dest_ip", "protocol",
			"bytes_in", "bytes_out", "packets_in", "packets_out",
		},

		// Optimization
		EarlyStopPatience: 5,
		UseGPU:           true,

		// Feature engineering
		FeatureNormalization: true,
		OutlierRemoval:      true,
		OutlierThreshold:    3.0,
	}
}

// Validate checks if the configuration is valid
func (c *ModelConfig) Validate() error {
	// TODO: Add validation logic for configuration parameters
	return nil
}