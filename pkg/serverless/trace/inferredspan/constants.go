// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package inferredspan

const (
	// Below are used for inferred span tagging and enrichment
	apiID            = "apiid"
	apiName          = "apiname"
	connectionID     = "connection_id"
	endpoint         = "endpoint"
	eventName        = "event_name"
	eventVersion     = "event_version"
	eventID          = "event_id"
	partitionKey     = "partition_key"
	eventType        = "event_type"
	eventSourceArn   = "event_source_arn"
	httpURL          = "http.url"
	httpMethod       = "http.method"
	httpProtocol     = "http.protocol"
	httpSourceIP     = "http.source_ip"
	httpUserAgent    = "http.user_agent"
	messageDirection = "message_direction"
	messageID        = "message_id"
	operationName    = "operation_name"
	queueName        = "queuename"
	receiptHandle    = "receipt_handle"
	requestID        = "request_id"
	resourceNames    = "resource_names"
	senderID         = "sender_id"
	sentTimestamp    = "SentTimestamp"
	shardID          = "shardid"
	stage            = "stage"
	streamName       = "streamname"
	subject          = "subject"
	topicName        = "topicname"
	topicARN         = "topic_arn"
	metadataType     = "type"

	// invocationType is used to look for the invocation type
	// in the payload headers
	invocationType = "X-Amz-Invocation-Type"
)
