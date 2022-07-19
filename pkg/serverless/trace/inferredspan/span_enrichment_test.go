// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package inferredspan

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/trace/pb"
	"github.com/stretchr/testify/assert"
)

const (
	dataFile = "../testdata/event_samples/"
)

func TestSetSynchronicityFalse(t *testing.T) {
	var attributes EventKeys
	var span InferredSpan
	attributes.Headers.InvocationType = ""
	span.GenerateInferredSpan(time.Now())
	span.IsAsync = isAsyncEvent(attributes)

	assert.False(t, span.IsAsync)
}

func TestSetSynchronicityTrue(t *testing.T) {
	var attributes EventKeys
	var span InferredSpan
	attributes.Headers.InvocationType = "Event"
	span.GenerateInferredSpan(time.Now())
	span.IsAsync = isAsyncEvent(attributes)

	assert.True(t, span.IsAsync)
}

func TestEnrichInferredSpanWithAPIGatewayRESTEvent(t *testing.T) {
	var eventKeys EventKeys
	_ = json.Unmarshal(getEventFromFile("api-gateway.json"), &eventKeys)
	inferredSpan := mockInferredSpan()
	inferredSpan.IsAsync = isAsyncEvent(eventKeys)
	inferredSpan.EnrichInferredSpanWithAPIGatewayRESTEvent(eventKeys)

	span := inferredSpan.Span

	assert.Equal(t, span.TraceID, uint64(7353030974370088224))
	assert.Equal(t, span.SpanID, uint64(8048964810003407541))
	assert.Equal(t, span.Start, int64(1428582896000000000))
	assert.Equal(t, span.Service, "70ixmpl4fl.execute-api.us-east-2.amazonaws.com")
	assert.Equal(t, span.Name, "aws.apigateway")
	assert.Equal(t, span.Resource, "POST /path/to/resource")
	assert.Equal(t, span.Type, "http")
	assert.Equal(t, span.Meta[APIID], "1234567890")
	assert.Equal(t, span.Meta[APIName], "1234567890")
	assert.Equal(t, span.Meta[Endpoint], "/path/to/resource")
	assert.Equal(t, span.Meta[HTTPURL], "70ixmpl4fl.execute-api.us-east-2.amazonaws.com/path/to/resource")
	assert.Equal(t, span.Meta[OperationName], "aws.apigateway.rest")
	assert.Equal(t, span.Meta[RequestID], "c6af9ac6-7b61-11e6-9a41-93e8deadbeef")
	assert.Equal(t, span.Meta[ResourceNames], "POST /path/to/resource")
	assert.Equal(t, span.Meta[Stage], "prod")
	assert.False(t, inferredSpan.IsAsync)
}

func TestEnrichInferredSpanWithAPIGatewayNonProxyAsyncRESTEvent(t *testing.T) {
	var eventKeys EventKeys
	_ = json.Unmarshal(getEventFromFile("api-gateway-non-proxy-async.json"), &eventKeys)
	inferredSpan := mockInferredSpan()
	inferredSpan.IsAsync = isAsyncEvent(eventKeys)
	inferredSpan.EnrichInferredSpanWithAPIGatewayRESTEvent(eventKeys)

	span := inferredSpan.Span
	assert.Equal(t, span.TraceID, uint64(7353030974370088224))
	assert.Equal(t, span.SpanID, uint64(8048964810003407541))
	assert.Equal(t, span.Start, int64(1631210915251000000))
	assert.Equal(t, span.Service, "lgxbo6a518.execute-api.sa-east-1.amazonaws.com")
	assert.Equal(t, span.Name, "aws.apigateway")
	assert.Equal(t, span.Resource, "GET /http/get")
	assert.Equal(t, span.Type, "http")
	assert.Equal(t, span.Meta[APIID], "lgxbo6a518")
	assert.Equal(t, span.Meta[APIName], "lgxbo6a518")
	assert.Equal(t, span.Meta[Endpoint], "/http/get")
	assert.Equal(t, span.Meta[HTTPURL], "lgxbo6a518.execute-api.sa-east-1.amazonaws.com/http/get")
	assert.Equal(t, span.Meta[OperationName], "aws.apigateway.rest")
	assert.Equal(t, span.Meta[RequestID], "7bf3b161-f698-432c-a639-6fef8b445137")
	assert.Equal(t, span.Meta[ResourceNames], "GET /http/get")
	assert.Equal(t, span.Meta[Stage], "dev")
	assert.True(t, inferredSpan.IsAsync)
}

func TestEnrichInferredSpanWithAPIGatewayHTTPEvent(t *testing.T) {
	var eventKeys EventKeys
	_ = json.Unmarshal(getEventFromFile("http-api.json"), &eventKeys)
	inferredSpan := mockInferredSpan()
	inferredSpan.EnrichInferredSpanWithAPIGatewayHTTPEvent(eventKeys)

	span := inferredSpan.Span
	assert.Equal(t, span.TraceID, uint64(7353030974370088224))
	assert.Equal(t, span.SpanID, uint64(8048964810003407541))
	assert.Equal(t, span.Start, int64(1631212283738000000))
	assert.Equal(t, span.Service, "x02yirxc7a.execute-api.sa-east-1.amazonaws.com")
	assert.Equal(t, span.Name, "aws.httpapi")
	assert.Equal(t, span.Resource, "GET ")
	assert.Equal(t, span.Type, "http")
	assert.Equal(t, span.Meta[HTTPMethod], "GET")
	assert.Equal(t, span.Meta[HTTPProtocol], "HTTP/1.1")
	assert.Equal(t, span.Meta[HTTPSourceIP], "38.122.226.210")
	assert.Equal(t, span.Meta[HTTPURL], "x02yirxc7a.execute-api.sa-east-1.amazonaws.com")
	assert.Equal(t, span.Meta[HTTPUserAgent], "curl/7.64.1")
	assert.Equal(t, span.Meta[OperationName], "aws.httpapi")
	assert.Equal(t, span.Meta[RequestID], "FaHnXjKCGjQEJ7A=")
	assert.Equal(t, span.Meta[ResourceNames], "GET ")
}

func TestEnrichInferredSpanWithAPIGatewayWebsocketDefaultEvent(t *testing.T) {
	var eventKeys EventKeys
	_ = json.Unmarshal(getEventFromFile("api-gateway-websocket-default.json"), &eventKeys)
	inferredSpan := mockInferredSpan()
	span := inferredSpan.Span

	inferredSpan.EnrichInferredSpanWithAPIGatewayWebsocketEvent(eventKeys)

	assert.Equal(t, span.TraceID, uint64(7353030974370088224))
	assert.Equal(t, span.SpanID, uint64(8048964810003407541))
	assert.Equal(t, span.Start, int64(1631285061365000000))
	assert.Equal(t, span.Service, "p62c47itsb.execute-api.sa-east-1.amazonaws.com")
	assert.Equal(t, span.Name, "aws.apigateway.websocket")
	assert.Equal(t, span.Resource, "$default")
	assert.Equal(t, span.Type, "web")
	assert.Equal(t, span.Meta[APIID], "p62c47itsb")
	assert.Equal(t, span.Meta[APIName], "p62c47itsb")
	assert.Equal(t, span.Meta[ConnectionID], "Fc5SzcoYGjQCJlg=")
	assert.Equal(t, span.Meta[Endpoint], "$default")
	assert.Equal(t, span.Meta[HTTPURL], "p62c47itsb.execute-api.sa-east-1.amazonaws.com$default")
	assert.Equal(t, span.Meta[MessageDirection], "IN")
	assert.Equal(t, span.Meta[OperationName], "aws.apigateway.websocket")
	assert.Equal(t, span.Meta[RequestID], "Fc5S3EvdGjQFtsQ=")
	assert.Equal(t, span.Meta[ResourceNames], "$default")
	assert.Equal(t, span.Meta[Stage], "dev")
}

func TestEnrichInferredSpanWithAPIGatewayWebsocketConnectEvent(t *testing.T) {
	var eventKeys EventKeys
	_ = json.Unmarshal(getEventFromFile("api-gateway-websocket-connect.json"), &eventKeys)
	inferredSpan := mockInferredSpan()
	span := inferredSpan.Span

	inferredSpan.EnrichInferredSpanWithAPIGatewayWebsocketEvent(eventKeys)

	assert.Equal(t, span.TraceID, uint64(7353030974370088224))
	assert.Equal(t, span.SpanID, uint64(8048964810003407541))
	assert.Equal(t, span.Start, int64(1631284003071000000))
	assert.Equal(t, span.Service, "p62c47itsb.execute-api.sa-east-1.amazonaws.com")
	assert.Equal(t, span.Name, "aws.apigateway.websocket")
	assert.Equal(t, span.Resource, "$connect")
	assert.Equal(t, span.Type, "web")
	assert.Equal(t, span.Meta[APIID], "p62c47itsb")
	assert.Equal(t, span.Meta[APIName], "p62c47itsb")
	assert.Equal(t, span.Meta[ConnectionID], "Fc2tgfl3mjQCJfA=")
	assert.Equal(t, span.Meta[Endpoint], "$connect")
	assert.Equal(t, span.Meta[HTTPURL], "p62c47itsb.execute-api.sa-east-1.amazonaws.com$connect")
	assert.Equal(t, span.Meta[MessageDirection], "IN")
	assert.Equal(t, span.Meta[OperationName], "aws.apigateway.websocket")
	assert.Equal(t, span.Meta[RequestID], "Fc2tgH1RmjQFnOg=")
	assert.Equal(t, span.Meta[ResourceNames], "$connect")
	assert.Equal(t, span.Meta[Stage], "dev")
}

func TestEnrichInferredSpanWithAPIGatewayWebsocketDisconnectEvent(t *testing.T) {
	var eventKeys EventKeys
	_ = json.Unmarshal(getEventFromFile("api-gateway-websocket-disconnect.json"), &eventKeys)
	inferredSpan := mockInferredSpan()
	span := inferredSpan.Span

	inferredSpan.EnrichInferredSpanWithAPIGatewayWebsocketEvent(eventKeys)

	assert.Equal(t, span.TraceID, uint64(7353030974370088224))
	assert.Equal(t, span.SpanID, uint64(8048964810003407541))
	assert.Equal(t, span.Start, int64(1631284034737000000))
	assert.Equal(t, span.Service, "p62c47itsb.execute-api.sa-east-1.amazonaws.com")
	assert.Equal(t, span.Name, "aws.apigateway.websocket")
	assert.Equal(t, span.Resource, "$disconnect")
	assert.Equal(t, span.Type, "web")
	assert.Equal(t, span.Meta[APIID], "p62c47itsb")
	assert.Equal(t, span.Meta[APIName], "p62c47itsb")
	assert.Equal(t, span.Meta[ConnectionID], "Fc2tgfl3mjQCJfA=")
	assert.Equal(t, span.Meta[Endpoint], "$disconnect")
	assert.Equal(t, span.Meta[HTTPURL], "p62c47itsb.execute-api.sa-east-1.amazonaws.com$disconnect")
	assert.Equal(t, span.Meta[MessageDirection], "IN")
	assert.Equal(t, span.Meta[OperationName], "aws.apigateway.websocket")
	assert.Equal(t, span.Meta[RequestID], "Fc2ydE4LmjQFhdg=")
	assert.Equal(t, span.Meta[ResourceNames], "$disconnect")
	assert.Equal(t, span.Meta[Stage], "dev")
}

func TestEnrichInferredSpanWithSNSEvent(t *testing.T) {
	var eventKeys EventKeys
	_ = json.Unmarshal(getEventFromFile("sns.json"), &eventKeys)
	inferredSpan := mockInferredSpan()
	inferredSpan.IsAsync = isAsyncEvent(eventKeys)
	inferredSpan.EnrichInferredSpanWithSNSEvent(eventKeys)

	span := inferredSpan.Span

	assert.Equal(t, span.TraceID, uint64(7353030974370088224))
	assert.Equal(t, span.SpanID, uint64(8048964810003407541))
	assert.Equal(t, span.Start, formatISOStartTime("2022-01-31T14:13:41.637Z"))
	assert.Equal(t, span.Service, "sns")
	assert.Equal(t, span.Name, "aws.sns")
	assert.Equal(t, span.Resource, "serverlessTracingTopicPy")
	assert.Equal(t, span.Type, "web")
	assert.Equal(t, span.Meta[MessageID], "87056a47-f506-5d77-908b-303605d3b197")
	assert.Equal(t, span.Meta[OperationName], "aws.sns")
	assert.Equal(t, span.Meta[ResourceNames], "serverlessTracingTopicPy")
	assert.Equal(t, span.Meta[Subject], "Hello")
	assert.Equal(t, span.Meta[TopicARN], "arn:aws:sns:sa-east-1:601427279990:serverlessTracingTopicPy")
	assert.Equal(t, span.Meta[TopicName], "serverlessTracingTopicPy")
	assert.Equal(t, span.Meta[Type], "Notification")
	assert.True(t, inferredSpan.IsAsync)
}

func TestEnrichInferredSpanWithSQSEvent(t *testing.T) {
	var sqsRequest events.SQSEvent
	_ = json.Unmarshal(getEventFromFile("sqs.json"), &sqsRequest)
	inferredSpan := mockInferredSpan()
	inferredSpan.EnrichInferredSpanWithSQSEvent(sqsRequest)

	span := inferredSpan.Span

	assert.Equal(t, uint64(7353030974370088224), span.TraceID)
	assert.Equal(t, uint64(8048964810003407541), span.SpanID)
	assert.Equal(t, int64(1634662094538000000), span.Start)
	assert.Equal(t, "sqs", span.Service)
	assert.Equal(t, "aws.sqs", span.Name)
	assert.Equal(t, "InferredSpansQueueNode", span.Resource)
	assert.Equal(t, "web", span.Type)
	assert.Equal(t, "aws.sqs", span.Meta[operationName])
	assert.Equal(t, "InferredSpansQueueNode", span.Meta[resourceNames])
	assert.Equal(t, "InferredSpansQueueNode", span.Meta[queueName])
	assert.Equal(t, "arn:aws:sqs:sa-east-1:601427279990:InferredSpansQueueNode", span.Meta[eventSourceArn])
	assert.Equal(t, "AQEBnxFcyzQZhkrLV/TrSpn0VBszuq4a5/u66uyGRdUKuvXMurd6RRV952L+arORbE4MlGqWLUxurzYH9mKvc/A3MYjmGwQvvhp6uK5c7gXxg6tvHVAlsEFmTB0p35dxfGCmtrJbzdPjVtmcucPEpRx7z51tQokgGWuJbqx3Z9MVRD+6dyO3o6Zu6G3oWUgiUZ0dxhNoIIeT6xr/tEsoWhGK9ZUPRJ7e0BM/UZKfkecX1CVgVZ8J/t8fHRklJd34S6pN99SPNBKx+1lOZCelm2MihbQR6zax8bkhwL3glxYP83MxexvfOELA3G/6jx96oQ4mQdJASsKFUzvcs2NUxX+0bBVX9toS7MW/Udv+3CiQwSjjkc18A385QHtNrJDRbH33OUxFCqN5CcUMiGvEFed5EQ==", span.Meta[receiptHandle])
	assert.Equal(t, "AROAYYB64AB3LSVUYFP5T:harv-inferred-spans-dev-initSender", span.Meta[senderID])
	assert.True(t, inferredSpan.IsAsync)
}

func TestEnrichInferredSpanWithDynamoDBEvent(t *testing.T) {
	var dynamoRequest events.DynamoDBEvent
	_ = json.Unmarshal(getEventFromFile("dynamodb.json"), &dynamoRequest)
	inferredSpan := mockInferredSpan()
	inferredSpan.EnrichInferredSpanWithDynamoDBEvent(dynamoRequest)

	span := inferredSpan.Span

	assert.Equal(t, uint64(7353030974370088224), span.TraceID)
	assert.Equal(t, uint64(8048964810003407541), span.SpanID)
	assert.Equal(t, time.Unix(1428537600, 0).UnixNano(), span.Start)
	assert.Equal(t, "dynamodb", span.Service)
	assert.Equal(t, "aws.dynamodb", span.Name)
	assert.Equal(t, "ExampleTableWithStream", span.Resource)
	assert.Equal(t, "web", span.Type)
	assert.Equal(t, "aws.dynamodb", span.Meta[operationName])
	assert.Equal(t, "ExampleTableWithStream", span.Meta[resourceNames])
	assert.Equal(t, "ExampleTableWithStream", span.Meta[tableName])
	assert.Equal(t, "arn:aws:dynamodb:us-east-1:123456789012:table/ExampleTableWithStream/stream/2015-06-27T00:48:05.899", span.Meta[eventSourceArn])
	assert.Equal(t, "c4ca4238a0b923820dcc509a6f75849b", span.Meta[eventID])
	assert.Equal(t, "INSERT", span.Meta[eventName])
	assert.Equal(t, "1.1", span.Meta[eventVersion])
	assert.Equal(t, "NEW_AND_OLD_IMAGES", span.Meta[streamViewType])
	assert.Equal(t, "26", span.Meta[sizeBytes])
	assert.True(t, inferredSpan.IsAsync)
}

func TestFormatISOStartTime(t *testing.T) {
	isotime := "2022-01-31T14:13:41.637Z"
	startTime := formatISOStartTime(isotime)
	assert.Equal(t, int64(1643638421637000000), startTime)

}

func TestFormatInvalidISOStartTime(t *testing.T) {
	isotime := "invalid"
	startTime := formatISOStartTime(isotime)
	assert.Equal(t, int64(0), startTime)
}

func getEventFromFile(filename string) []byte {
	event, _ := os.ReadFile(dataFile + filename)
	return event
}

func mockInferredSpan() InferredSpan {
	var inferredSpan InferredSpan
	inferredSpan.Span = &pb.Span{}
	inferredSpan.Span.TraceID = uint64(7353030974370088224)
	inferredSpan.Span.SpanID = uint64(8048964810003407541)
	return inferredSpan
}

func TestCalculateStartTime(t *testing.T) {
	assert.Equal(t, int64(1651863561696000000), calculateStartTime(1651863561696))
}
