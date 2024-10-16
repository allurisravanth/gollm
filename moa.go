package gollm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/allurisravanth/gollm/config"
	"github.com/allurisravanth/gollm/llm"
	"github.com/allurisravanth/gollm/providers"
	"github.com/allurisravanth/gollm/utils"
)

// MOAConfig represents the configuration for the Mixture of Agents
type MOAConfig struct {
	Iterations   int
	Models       []ConfigOption // Change this to ConfigOption
	MaxParallel  int
	AgentTimeout time.Duration
}

// MOALayer represents a single layer in the Mixture of Agents
type MOALayer struct {
	Models []llm.LLM
}

// MOA represents the Mixture of Agents
type MOA struct {
	Config     MOAConfig
	Layers     []MOALayer
	Aggregator llm.LLM
}

// NewMOA creates a new Mixture of Agents instance
func NewMOA(moaConfig MOAConfig, aggregatorOpts ...ConfigOption) (*MOA, error) {
	if len(moaConfig.Models) == 0 {
		return nil, fmt.Errorf("invalid model configuration: at least one model must be specified")
	}

	registry := providers.NewProviderRegistry()
	logger := utils.NewLogger(utils.LogLevelInfo)

	moa := &MOA{
		Config: moaConfig,
		Layers: make([]MOALayer, len(moaConfig.Models)),
	}

	// Initialize each layer with its corresponding model
	for i, modelOpt := range moaConfig.Models {
		cfg := &config.Config{}
		modelOpt(cfg)
		llmInstance, err := llm.NewLLM(cfg, logger, registry)
		if err != nil {
			return nil, fmt.Errorf("failed to create LLM for model %d: %w", i, err)
		}
		moa.Layers[i] = MOALayer{
			Models: []llm.LLM{llmInstance},
		}
	}

	// Create the aggregator LLM
	aggregatorConfig := &config.Config{}
	for _, opt := range aggregatorOpts {
		opt(aggregatorConfig)
	}
	aggregator, err := llm.NewLLM(aggregatorConfig, logger, registry)
	if err != nil {
		return nil, fmt.Errorf("failed to create aggregator LLM: %w", err)
	}
	moa.Aggregator = aggregator

	return moa, nil
}

// Generate processes the input through the Mixture of Agents and returns the final output
func (moa *MOA) Generate(ctx context.Context, input string) (string, error) {
	var layerOutputs []string

	// Process through each iteration
	for i := 0; i < moa.Config.Iterations; i++ {
		layerInput := input
		// Process each layer
		for _, layer := range moa.Layers {
			layerOutput, err := moa.processLayer(ctx, layer, layerInput)
			if err != nil {
				return "", fmt.Errorf("error processing layer: %w", err)
			}
			layerInput = layerOutput
		}
		layerOutputs = append(layerOutputs, layerInput)
	}

	// Aggregate the results from all iterations
	return moa.aggregate(ctx, layerOutputs)
}

// processLayer handles the processing of a single layer, potentially in parallel
func (moa *MOA) processLayer(ctx context.Context, layer MOALayer, input string) (string, error) {
	results := make([]string, len(layer.Models))
	errors := make([]error, len(layer.Models))

	// Create a worker pool if parallel processing is enabled
	var wg sync.WaitGroup
	var workerPool chan struct{}
	if moa.Config.MaxParallel > 0 {
		workerPool = make(chan struct{}, moa.Config.MaxParallel)
	}

	for i, model := range layer.Models {
		wg.Add(1)
		go func(index int, llmInstance llm.LLM) {
			defer wg.Done()
			if workerPool != nil {
				workerPool <- struct{}{}        // Acquire a worker
				defer func() { <-workerPool }() // Release the worker
			}

			// Create a context with timeout if AgentTimeout is set
			var cancel context.CancelFunc
			if moa.Config.AgentTimeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, moa.Config.AgentTimeout)
				defer cancel()
			}

			output, err := llmInstance.Generate(ctx, llm.NewPrompt(input))
			if err != nil {
				errors[index] = err
				return
			}
			results[index] = output
		}(i, model)
	}

	wg.Wait()

	// Check for errors
	for _, err := range errors {
		if err != nil {
			return "", fmt.Errorf("error in layer processing: %w", err)
		}
	}

	return moa.combineResults(results), nil
}

// combineResults merges the results from multiple models in a layer
func (moa *MOA) combineResults(results []string) string {
	combined := ""
	for _, result := range results {
		combined += result + "\n---\n"
	}
	return combined
}

// aggregate uses the aggregator LLM to synthesise the final output
func (moa *MOA) aggregate(ctx context.Context, outputs []string) (string, error) {
	aggregationPrompt := fmt.Sprintf("Synthesise these responses into a single, high-quality response:\n\n%s", moa.combineResults(outputs))
	response, err := moa.Aggregator.Generate(ctx, llm.NewPrompt(aggregationPrompt))

	return response, err
}
