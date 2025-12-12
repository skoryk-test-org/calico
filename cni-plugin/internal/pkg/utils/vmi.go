// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package utils

import (
	corev1 "k8s.io/api/core/v1"
)

// KubeVirt label keys
const (
	// LabelKubeVirt is the label that identifies a virt-launcher pod
	LabelKubeVirt = "kubevirt.io"
	// LabelKubeVirtCreatedBy contains the VMI UID
	LabelKubeVirtCreatedBy = "kubevirt.io/created-by"
	// LabelKubeVirtMigrationJobUID is only present on migration target pods
	LabelKubeVirtMigrationJobUID = "kubevirt.io/migrationJobUID"
	// LabelKubeVirtVMName contains the VM/VMI name
	LabelKubeVirtVMName = "vm.kubevirt.io/name"

	// ValueVirtLauncher is the value of LabelKubeVirt for virt-launcher pods
	ValueVirtLauncher = "virt-launcher"
)

// VMIInfo contains KubeVirt VMI-related information extracted from pod labels
type VMIInfo struct {
	// VMIName is the name of the VirtualMachineInstance (from vm.kubevirt.io/name)
	VMIName string
	// VMIUID is the UID of the VirtualMachineInstance (from kubevirt.io/created-by)
	VMIUID string
	// MigrationJobUID is the UID of the migration job (from kubevirt.io/migrationJobUID)
	// This is only present on migration target pods
	MigrationJobUID string
	// isVirtLauncher indicates if this pod is a virt-launcher pod
	isVirtLauncher bool
}

// GetVMIInfo extracts VMI information from a pod's labels.
// Returns a VMIInfo struct with all available VMI-related information.
func GetVMIInfo(pod *corev1.Pod) *VMIInfo {
	if pod == nil || pod.Labels == nil {
		return &VMIInfo{}
	}

	info := &VMIInfo{}

	// Check if this is a virt-launcher pod
	if pod.Labels[LabelKubeVirt] == ValueVirtLauncher {
		info.isVirtLauncher = true
	}

	// Extract VMI UID
	if uid, ok := pod.Labels[LabelKubeVirtCreatedBy]; ok {
		info.VMIUID = uid
	}

	// Extract VMI name
	if name, ok := pod.Labels[LabelKubeVirtVMName]; ok {
		info.VMIName = name
	}

	// Extract migration job UID (only present on target pods during migration)
	if migrationUID, ok := pod.Labels[LabelKubeVirtMigrationJobUID]; ok {
		info.MigrationJobUID = migrationUID
	}

	return info
}

// IsVirtLauncherPod returns true if the pod is a KubeVirt virt-launcher pod
func (v *VMIInfo) IsVirtLauncherPod() bool {
	return v.isVirtLauncher
}

// IsMigrationTarget returns true if this pod is a migration target pod.
// Migration target pods have the kubevirt.io/migrationJobUID label set.
func (v *VMIInfo) IsMigrationTarget() bool {
	return v.MigrationJobUID != ""
}

// HasVMIUID returns true if the VMI UID is available
func (v *VMIInfo) HasVMIUID() bool {
	return v.VMIUID != ""
}

// GetVMIName returns the VMI name
func (v *VMIInfo) GetVMIName() string {
	return v.VMIName
}

// GetVMIUID returns the VMI UID
func (v *VMIInfo) GetVMIUID() string {
	return v.VMIUID
}

