// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build orchestrator
// +build orchestrator

package k8s

import (
	"fmt"
	model "github.com/DataDog/agent-payload/v5/process"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/objectmeta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	strings "strings"
)

// ExtractCustomResource returns the protobuf model corresponding to a
// Kubernetes ClusterRole resource.
func ExtractCustomResource(u *unstructured.Unstructured) *model.ClusterRole {
	clusterRole := &model.ClusterRole{
		Metadata: extractUnstructuredMetadata(u.Object),
	}
	return clusterRole
}

func extractUnstructuredMetadata(cr map[string]interface{}) *model.Metadata {
	meta, _, err := objectmeta.GetObjectMeta(cr, true)
	if err != nil {
		return nil
	}

	return extractMetadata(meta)
}

func getKeyByField(key string, cr *unstructured.Unstructured) interface{} {
	words := strings.Split(key, ".")
	obj := cr.Object
	for i, s := range words {
		// last iteration means no further object to traverse
		if i == len(words)-1 {
			field, _, err := unstructured.NestedFieldNoCopy(obj, s)
			if err != nil {
				return ""
			}
			return field
		} else {
			obj2, _, err := nestedMap(obj, s)
			if err != nil {
				return ""
			}
			obj = obj2
		}
	}
	return ""
}

func nestedMap(obj map[string]interface{}, fields ...string) (map[string]interface{}, bool, error) {
	val, found, err := unstructured.NestedFieldNoCopy(obj, fields...)
	if !found || err != nil {
		return nil, found, err
	}
	m, ok := val.(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("accessor error: %v is of the type %T, expected map[string]interface{}", val, val)
	}
	return m, true, nil
}
