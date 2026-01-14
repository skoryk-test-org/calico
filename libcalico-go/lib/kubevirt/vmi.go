// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

// This file provides utilities for working with KubeVirt VirtualMachineInstance (VMI) pods.
//
// KubeVirt virt-launcher pods contain labels that identify the VMI and track live migration state.
// Example pod labels for a virt-launcher pod:
//
//	labels:
//	  kubevirt.io: virt-launcher
//	  kubevirt.io/created-by: d2ad3ee8-1082-4d61-8202-dbc2432cdd88  # VMI UID
//	  kubevirt.io/migrationJobUID: 122eae59-b197-42c1-a58d-67248f8e5be9  # <--- ONLY ON TARGET POD
//	  vm.kubevirt.io/name: vm1
//
// During live migration:
//   - Source pod: Has kubevirt.io/created-by (VMI UID), does NOT have migrationJobUID
//   - Target pod: Has both kubevirt.io/created-by (same VMI UID) AND migrationJobUID
//
// The VMI UID (kubevirt.io/created-by) remains stable across pod recreations and migrations,
// making it suitable as a basis for IPAM handle IDs to ensure IP address persistence.
package kubevirt

import (
	"fmt"

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
	VMIName         string
	VMIUID          string
	MigrationJobUID string

	// isVirtLauncher indicates if this pod is a virt-launcher pod
	isVirtLauncher bool
}

// GetVMIInfo extracts VMI information from a pod's labels.
// Returns:
//   - (*VMIInfo, nil) if the pod is a valid virt-launcher pod with all required labels
//   - (nil, nil) if the pod is not a virt-launcher pod
//   - (nil, error) if the pod is a virt-launcher pod but missing critical labels (VMIUID or VMIName)
func GetVMIInfo(pod *corev1.Pod) (*VMIInfo, error) {
	if pod == nil || pod.Labels == nil {
		return nil, nil
	}

	// Check if this is a virt-launcher pod
	if pod.Labels[LabelKubeVirt] != ValueVirtLauncher {
		// Not a virt-launcher pod
		return nil, nil
	}

	info := &VMIInfo{
		isVirtLauncher: true,
	}

	// Extract and validate VMI UID
	if uid, ok := pod.Labels[LabelKubeVirtCreatedBy]; ok && uid != "" {
		info.VMIUID = uid
	} else {
		return nil, fmt.Errorf("virt-launcher pod %s/%s is missing required label %s",
			pod.Namespace, pod.Name, LabelKubeVirtCreatedBy)
	}

	// Extract and validate VMI name
	if name, ok := pod.Labels[LabelKubeVirtVMName]; ok && name != "" {
		info.VMIName = name
	} else {
		return nil, fmt.Errorf("virt-launcher pod %s/%s is missing required label %s",
			pod.Namespace, pod.Name, LabelKubeVirtVMName)
	}

	// Extract migration job UID (optional - only present on target pods during migration)
	if migrationUID, ok := pod.Labels[LabelKubeVirtMigrationJobUID]; ok {
		info.MigrationJobUID = migrationUID
	}

	// Verify VMI ownership to prevent label spoofing
	// Check if the pod has an ownerReference with matching VMI UID
	if err := verifyVMIOwnership(pod, info.VMIUID); err != nil {
		return nil, fmt.Errorf("VMI ownership verification failed for pod %s/%s: %w",
			pod.Namespace, pod.Name, err)
	}

	return info, nil
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

// GetVMIName returns the VMI name
func (v *VMIInfo) GetVMIName() string {
	return v.VMIName
}

// GetVMIUID returns the VMI UID
func (v *VMIInfo) GetVMIUID() string {
	return v.VMIUID
}

// GetVMIMigrationUID returns the migration job UID.
// Returns empty string if this is not a migration target pod.
func (v *VMIInfo) GetVMIMigrationUID() string {
	return v.MigrationJobUID
}

// verifyVMIOwnership validates that the pod is actually owned by the VMI with the given UID.
// This prevents users from spoofing virt-launcher behavior by adding labels to normal pods.
// KubeVirt sets the VirtualMachineInstance as the controller owner of virt-launcher pods.
func verifyVMIOwnership(pod *corev1.Pod, vmiUID string) error {
	if pod.OwnerReferences == nil || len(pod.OwnerReferences) == 0 {
		return fmt.Errorf("virt-launcher pod has no owner references")
	}

	// Look for a VirtualMachineInstance owner with matching UID
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "VirtualMachineInstance" {
			if string(owner.UID) == vmiUID {
				// Found matching VMI owner - verification successful
				return nil
			}
			// Found VMI owner but UID doesn't match - this is suspicious
			return fmt.Errorf("VMI UID mismatch: label has %s but owner reference has %s", vmiUID, owner.UID)
		}
	}

	// No VirtualMachineInstance owner found
	return fmt.Errorf("no VirtualMachineInstance owner reference found (VMI UID from label: %s)", vmiUID)
}
