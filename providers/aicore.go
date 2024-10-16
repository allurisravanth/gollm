package providers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/allurisravanth/gollm/config"
	"github.com/allurisravanth/gollm/providers"
	"github.com/allurisravanth/gollm/utils"
)

type AicoreProvider struct {
	model        string
	extraHeaders map[string]string
	options      map[string]interface{}
	logger       utils.Logger
}

func NewAicoreProvider(apiKey, model string, extraHeaders map[string]string) providers.Provider {
	if extraHeaders == nil {
		extraHeaders = make(map[string]string)
	}
	return &AicoreProvider{
		model:        model,
		extraHeaders: extraHeaders,
		options:      make(map[string]interface{}),
		logger:       utils.NewLogger(utils.LogLevelInfo),
	}
}

func (p *AicoreProvider) SetLogger(logger utils.Logger) {
	p.logger = logger
}

// SetOption sets a specific option for the provider
func (p *AicoreProvider) SetOption(key string, value interface{}) {
	p.options[key] = value
	p.logger.Debug("Option set", "key", key, "value", value)
}

// SetDefaultOptions sets default options based on the provided configuration
func (p *AicoreProvider) SetDefaultOptions(config *config.Config) {
	p.SetOption("temperature", config.Temperature)
	p.SetOption("max_tokens", config.MaxTokens)
	if config.Seed != nil {
		p.SetOption("seed", *config.Seed)
	}
	p.logger.Debug("Default options set", "temperature", config.Temperature, "max_tokens", config.MaxTokens, "seed", config.Seed)
}

// Name returns the provider's name
func (p *AicoreProvider) Name() string {
	return "aicore"
}

// Endpoint returns the API endpoint for OpenAI
func (p *AicoreProvider) Endpoint() string {
	aiApiUrl := "https://api.ai.prod.eu-central-1.aws.ml.hana.ondemand.com"
	completionsDeploymentId := "d4396b535cecfef2"

	url := aiApiUrl + "/v2/inference/deployments/" + completionsDeploymentId + "/chat/completions?api-version=2023-05-15"
	return url
}

type Token struct {
	AccessToken string `json:"access_token"`
}

func (p *AicoreProvider) GetToken() string {
	var (
		xsuaaUrl     string
		clientId     string
		clientSecret string
	)
	//xsuaaUrl = os.Getenv("XSUAA_URL")
	//clientId = os.Getenv("CLIENT_ID")
	//clientSecret = os.Getenv("CLIENT_SECRET")

	xsuaaUrl = "https://sapml.authentication.eu10.hana.ondemand.com"
	clientId = "sb-979eb591-0dd3-4119-9398-f5870d1bc91f!b540|aicore!b540"
	clientSecret = "0aQ2hhVGGXsw4eK289YwMN9dX+4="

	url := xsuaaUrl + "/oauth/token?grant_type=client_credentials"
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
	}
	req.Header.Add("Content-Type", "application/json")
	//create base64 encoding
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientId+":"+clientSecret)))

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}
	var token Token
	err = json.Unmarshal(body, &token)
	if err != nil {
		return ""
	}
	return token.AccessToken
}

// SupportsJSONSchema indicates whether this provider supports JSON schema
func (p *AicoreProvider) SupportsJSONSchema() bool {
	return true
}

// Headers returns the necessary headers for API requests
func (p *AicoreProvider) Headers() map[string]string {
	headers := map[string]string{
		"Content-Type":      "application/json",
		"AI-Resource-Group": "default",
		"Authorization":     "Bearer " + p.GetToken(),
	}

	for key, value := range p.extraHeaders {
		headers[key] = value
	}

	p.logger.Debug("Headers prepared", "headers", headers)
	return headers
}

// PrepareRequest prepares the request body for the API call
func (p *AicoreProvider) PrepareRequest(prompt string, options map[string]interface{}) ([]byte, error) {
	request := map[string]interface{}{
		"model": p.model,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}

	// Handle tool_choice
	if toolChoice, ok := options["tool_choice"].(string); ok {
		request["tool_choice"] = toolChoice
	}

	// Handle tools
	if tools, ok := options["tools"].([]utils.Tool); ok && len(tools) > 0 {
		openAITools := make([]map[string]interface{}, len(tools))
		for i, tool := range tools {
			openAITools[i] = map[string]interface{}{
				"type": "function",
				"function": map[string]interface{}{
					"name":        tool.Function.Name,
					"description": tool.Function.Description,
					"parameters":  tool.Function.Parameters,
				},
				"strict": true, // Add this if you want strict mode
			}
		}
		request["tools"] = openAITools
	}

	// Add other options
	for k, v := range p.options {
		if k != "tools" && k != "tool_choice" {
			request[k] = v
		}
	}
	for k, v := range options {
		if k != "tools" && k != "tool_choice" {
			request[k] = v
		}
	}

	return json.Marshal(request)
}

// createBaseRequest creates the base request structure
func (p *AicoreProvider) createBaseRequest(prompt string) map[string]interface{} {
	var request map[string]interface{}
	if err := json.Unmarshal([]byte(prompt), &request); err != nil {
		p.logger.Debug("Prompt is not a valid JSON, creating standard request", "error", err)
		request = map[string]interface{}{
			"model": p.model,
			"messages": []interface{}{
				map[string]interface{}{
					"role":    "user",
					"content": prompt,
				},
			},
		}
	}
	return request
}

// processMessages processes the messages in the request
func (p *AicoreProvider) processMessages(request map[string]interface{}) {
	p.logger.Debug("Processing messages")
	if messages, ok := request["messages"]; ok {
		switch msg := messages.(type) {
		case []interface{}:
			for i, m := range msg {
				if msgMap, ok := m.(map[string]interface{}); ok {
					p.processFunctionMessage(msgMap)
					msg[i] = msgMap
				}
			}
		case []map[string]string:
			newMessages := make([]interface{}, len(msg))
			for i, m := range msg {
				msgMap := make(map[string]interface{})
				for k, v := range m {
					msgMap[k] = v
				}
				p.processFunctionMessage(msgMap)
				newMessages[i] = msgMap
			}
			request["messages"] = newMessages
		default:
			p.logger.Warn("Unexpected type for messages", "type", fmt.Sprintf("%T", messages))
		}
	}
	p.logger.Debug("Messages processed", "messageCount", len(request["messages"].([]interface{})))
}

// processFunctionMessage handles function messages
func (p *AicoreProvider) processFunctionMessage(msgMap map[string]interface{}) {
	if msgMap["role"] == "function" && msgMap["name"] == nil {
		if content, ok := msgMap["content"].(string); ok {
			var contentMap map[string]interface{}
			if err := json.Unmarshal([]byte(content), &contentMap); err == nil {
				if name, ok := contentMap["name"].(string); ok {
					msgMap["name"] = name
					p.logger.Debug("Function name extracted from content", "name", name)
				}
			}
		}
	}
}

// processToolCalls handles tool calls in messages
func (p *AicoreProvider) processToolCalls(msgMap map[string]interface{}) {
	if toolCalls, ok := msgMap["tool_calls"].([]interface{}); ok {
		for j, call := range toolCalls {
			if callMap, ok := call.(map[string]interface{}); ok {
				if function, ok := callMap["function"].(map[string]interface{}); ok {
					if args, ok := function["arguments"].(string); ok {
						var parsedArgs map[string]interface{}
						if err := json.Unmarshal([]byte(args), &parsedArgs); err == nil {
							function["arguments"] = parsedArgs
							callMap["function"] = function
							toolCalls[j] = callMap
							p.logger.Debug("Tool call arguments parsed", "functionName", function["name"], "arguments", parsedArgs)
						}
					}
				}
			}
		}
		msgMap["tool_calls"] = toolCalls
	}
}

// addOptions adds options to the request
func (p *AicoreProvider) addOptions(request map[string]interface{}, options map[string]interface{}) {
	for k, v := range p.options {
		request[k] = v
	}
	for k, v := range options {
		request[k] = v
	}
	p.logger.Debug("Options added to request", "options", options)
}

// PrepareRequestWithSchema prepares a request with a JSON schema
func (p *AicoreProvider) PrepareRequestWithSchema(prompt string, options map[string]interface{}, schema interface{}) ([]byte, error) {
	p.logger.Debug("Preparing request with schema", "prompt", prompt, "schema", schema)
	request := map[string]interface{}{
		"model": p.model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"response_format": map[string]interface{}{
			"type":   "json_schema",
			"schema": schema,
		},
	}

	for k, v := range options {
		request[k] = v
	}

	reqJSON, err := json.Marshal(request)
	if err != nil {
		p.logger.Error("Failed to marshal request with schema", "error", err)
		return nil, err
	}

	p.logger.Debug("Request with schema prepared", "request", string(reqJSON))
	return reqJSON, nil
}

// ParseResponse parses the API response
func (p *AicoreProvider) ParseResponse(body []byte) (string, error) {
	var response struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	message := response.Choices[0].Message
	if message.Content != "" {
		return message.Content, nil
	}

	if len(message.ToolCalls) > 0 {
		toolCallJSON, err := json.Marshal(message.ToolCalls)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("<function_call>%s</function_call>", toolCallJSON), nil
	}

	return "", fmt.Errorf("no content or tool calls in response")
}

func (p *AicoreProvider) HandleFunctionCalls(body []byte) ([]byte, error) {
	var response struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if len(response.Choices) == 0 || len(response.Choices[0].Message.ToolCalls) == 0 {
		return nil, fmt.Errorf("no tool calls found in response")
	}

	toolCalls := response.Choices[0].Message.ToolCalls
	result := make([]map[string]interface{}, len(toolCalls))
	for i, call := range toolCalls {
		var args map[string]interface{}
		if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
			return nil, fmt.Errorf("error parsing arguments: %w", err)
		}
		result[i] = map[string]interface{}{
			"name":      call.Function.Name,
			"arguments": args,
		}
	}

	return json.Marshal(result)
}

// mustMarshal is a helper function to marshal JSON and panic on error
func mustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// SetExtraHeaders sets additional headers for the API request
func (p *AicoreProvider) SetExtraHeaders(extraHeaders map[string]string) {
	p.extraHeaders = extraHeaders
	p.logger.Debug("Extra headers set", "headers", extraHeaders)
}
