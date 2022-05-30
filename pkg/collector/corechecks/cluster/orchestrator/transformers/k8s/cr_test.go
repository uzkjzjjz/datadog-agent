/*
 * Unless explicitly stated otherwise all files in this repository are licensed
 * under the Apache License Version 2.0.
 * This product includes software developed at Datadog (https://www.datadoghq.com/).
 * Copyright 2016-2022 Datadog, Inc.
 */

package k8s

import (
	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"testing"
	"time"
)

func TestExtractMetadata(t *testing.T) {

	tests := []struct {
		name                  string
		unstructuredToConvert *unstructured.Unstructured
		want                  *model.Metadata
	}{
		{
			name: "convert valid versioned unstructured to versioned object should work",
			unstructuredToConvert: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Carp",
					"metadata": map[string]interface{}{
						"creationTimestamp": nil,
						"name":              "noxu",
					},
					"spec": map[string]interface{}{
						"hostname": "example.com",
					},
					"status": map[string]interface{}{},
				},
			},
			want: &model.Metadata{
				Name: "noxu",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: fix types
			assert.Equalf(t, tt.want, extractUnstructuredMetadata(tt.unstructuredToConvert.Object), "extractMetadata(%v)", tt.want)
		})
	}
}

func TestExtractMetadataRoundTrip(t *testing.T) {
	now := time.Now()

	pod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "a",
			UID:               "uid",
			ResourceVersion:   "rv",
			Generation:        2,
			CreationTimestamp: metav1.Time{Time: now},
		},
	}

	expected := model.Metadata{
		Name:              "test",
		Namespace:         "a",
		Uid:               "uid",
		CreationTimestamp: now.Unix(),
		ResourceVersion:   "rv",
	}

	us, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pod)
	assert.NoError(t, err)
	metadata := extractUnstructuredMetadata(us)
	assert.Equal(t, &expected, metadata)

}

func TestGetKeyByField(t *testing.T) {
	key := "spec.setting.lowWaterMark"
	unstructuredToConvert := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Carp",
			"metadata": map[string]interface{}{
				"creationTimestamp": nil,
				"name":              "noxu",
			},
			"spec": map[string]interface{}{
				"setting": map[string]interface{}{
					"lowWaterMark": 10,
				},
			},
			"status": map[string]interface{}{},
		},
	}
	actual := getKeyByField(key, unstructuredToConvert)
	assert.Equal(t, 10, actual)
}
