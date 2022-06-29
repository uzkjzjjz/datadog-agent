// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package probe

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

// GetEvent return a model.Event from the eval.Context
func GetEvent(ctx *eval.Context) *model.Event {
	return (*model.Event)(ctx.Event)
}

// GetUserData return the user data from the context
func GetUserData(ctx *eval.Context) *Resolvers {
	return (*Resolvers)(ctx.UserData)
}
