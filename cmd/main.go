package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloudwego/eino"
	"github.com/gin-gonic/gin"
	"github.com/jinye/securityai/api/handler"
	"github.com/jinye/securityai/internal/ai/anomaly"
	"github.com/jinye/securityai/internal/service/log"
)

func main() {
	// Create context that listens for the interrupt signal from the OS
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Initialize configuration
	config, err := initConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize Eino engine
	engine, err := eino.NewEngine(eino.Config{
		// Configure Eino engine based on your needs
	})
	if err != nil {
		log.Fatalf("Failed to initialize Eino engine: %v", err)
	} // 初始化仓储层
	eventRepo := initEventRepository(config)
	vectorRepo := initVectorRepository(config)
	cacheRepo := initCacheRepository(config)

	// 初始化告警管理器
	alertManager := initAlertManager(config)

	// 初始化异常检测器
	detector, err := anomaly.NewAnomalyDetector(
		engine,
		config.AI.ModelPath,
		eventRepo,
		vectorRepo,
		config.AI.Threshold,
		config.AI.BatchSize,
	)
	if err != nil {
		log.Fatalf("Failed to initialize anomaly detector: %v", err)
	}

	// Initialize log enricher
	enricher := initLogEnricher(config)

	// Initialize log processor
	logProcessor := log.NewLogProcessor(
		detector,
		eventRepo,
		cacheRepo,
		enricher,
	)

	// Initialize Gin router
	router := gin.Default()

	// Initialize and register handlers
	securityHandler := handler.NewSecurityHandler(logProcessor, eventRepo)
	securityHandler.RegisterRoutes(router)

	// Start the server
	srv := &http.Server{
		Addr:    ":" + config.Server.Port,
		Handler: router,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		log.Println("Shutting down server...")

		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Server forced to shutdown: %v", err)
		}
	}()

	// Start server
	log.Printf("Server starting on port %s", config.Server.Port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func initConfig() (*Config, error) {
	// TODO: Implement configuration loading
	return nil, nil
}

func initEventRepository(config *Config) repository.EventRepository {
	// TODO: Implement repository initialization
	return nil
}

func initVectorRepository(config *Config) repository.VectorRepository {
	// TODO: Implement repository initialization
	return nil
}

func initCacheRepository(config *Config) repository.CacheRepository {
	// TODO: Implement repository initialization
	return nil
}

func initLogEnricher(config *Config) *log.LogEnricher {
	// TODO: Implement log enricher initialization
	return nil
}
