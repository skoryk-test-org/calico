// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file provides utilities for creating KubeVirt clients.
package kubevirt

import (
	"fmt"

	"k8s.io/client-go/tools/clientcmd"
	"kubevirt.io/client-go/kubecli"
)

// GetVirtClientFromConfig creates a KubeVirt client from a clientcmd.ClientConfig
func GetVirtClientFromConfig(clientConfig clientcmd.ClientConfig) (kubecli.KubevirtClient, error) {
	virtClient, err := kubecli.GetKubevirtClientFromClientConfig(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain KubeVirt client: %w", err)
	}
	return virtClient, nil
}
