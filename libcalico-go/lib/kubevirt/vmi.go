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
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubevirt.io/client-go/kubecli"
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

	// VMI API Group, Version, and Resource for dynamic client
	VMIGroup        = "kubevirt.io"
	VMIVersion      = "v1"
	VMIResourceName = "virtualmachineinstances"
)

// PodVMIInfo contains KubeVirt VMI-related information extracted from pod labels
type PodVMIInfo struct {
	VMIName         string
	VMIUID          string
	MigrationJobUID string

	// isVirtLauncher indicates if this pod is a virt-launcher pod
	isVirtLauncher bool
}

// VMIResource contains information about a VirtualMachineInstance resource queried from the Kubernetes API
type VMIResource struct {
	// Name is the VMI name
	Name string
	// Namespace is the VMI namespace
	Namespace string
	// UID is the VMI UID
	UID string
	// DeletionTimestamp indicates when the VMI was marked for deletion
	// If nil, the VMI is not being deleted
	DeletionTimestamp *metav1.Time
	// CreationTimestamp is when the VMI was created
	CreationTimestamp metav1.Time
}

// IsDeletionInProgress returns true if the VMI has a deletion timestamp set
func (v *VMIResource) IsDeletionInProgress() bool {
	return v.DeletionTimestamp != nil && !v.DeletionTimestamp.IsZero()
}

// GetDeletionGracePeriod returns the time since deletion timestamp was set
// Returns 0 if VMI is not being deleted
func (v *VMIResource) GetDeletionGracePeriod() time.Duration {
	if !v.IsDeletionInProgress() {
		return 0
	}
	return time.Since(v.DeletionTimestamp.Time)
}

// GetPodVMIInfo extracts VMI information from a pod's labels.
// Returns:
//   - (*PodVMIInfo, nil) if the pod is a valid virt-launcher pod with all required labels
//   - (nil, nil) if the pod is not a virt-launcher pod
//   - (nil, error) if the pod is a virt-launcher pod but missing critical labels (VMIUID or VMIName)
func GetPodVMIInfo(pod *corev1.Pod) (*PodVMIInfo, error) {
	if pod == nil || pod.Labels == nil {
		return nil, nil
	}

	// Check if this is a virt-launcher pod
	if pod.Labels[LabelKubeVirt] != ValueVirtLauncher {
		// Not a virt-launcher pod
		return nil, nil
	}

	info := &PodVMIInfo{
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
func (v *PodVMIInfo) IsVirtLauncherPod() bool {
	return v.isVirtLauncher
}

// IsMigrationTarget returns true if this pod is a migration target pod.
// Migration target pods have the kubevirt.io/migrationJobUID label set.
func (v *PodVMIInfo) IsMigrationTarget() bool {
	return v.MigrationJobUID != ""
}

// GetVMIName returns the VMI name
func (v *PodVMIInfo) GetVMIName() string {
	return v.VMIName
}

// GetVMIUID returns the VMI UID
func (v *PodVMIInfo) GetVMIUID() string {
	return v.VMIUID
}

// GetVMIMigrationUID returns the migration job UID.
// Returns empty string if this is not a migration target pod.
func (v *PodVMIInfo) GetVMIMigrationUID() string {
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

// GetVMIResourceByUID queries the Kubernetes API for a VirtualMachineInstance with the given UID
// and returns a VMIResource containing its metadata.
// Returns:
//   - (*VMIResource, nil) if the VMI is found
//   - (nil, error) if there was an error querying the API or VMI not found
func GetVMIResourceByUID(ctx context.Context, virtClient kubecli.KubevirtClient, namespace, vmiUID string) (*VMIResource, error) {
	// List VMIs in the namespace
	vmiList, err := virtClient.VirtualMachineInstance(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list VMIs in namespace %s: %w", namespace, err)
	}

	// Find the VMI with matching UID
	for _, vmi := range vmiList.Items {
		if string(vmi.UID) == vmiUID {
			// Found the VMI, populate VMIResource
			return &VMIResource{
				Name:              vmi.Name,
				Namespace:         vmi.Namespace,
				UID:               string(vmi.UID),
				CreationTimestamp: vmi.CreationTimestamp,
				DeletionTimestamp: vmi.DeletionTimestamp,
			}, nil
		}
	}

	// VMI with given UID not found
	return nil, fmt.Errorf("VMI with UID %s not found in namespace %s", vmiUID, namespace)
}

// GetVMIResourceByName queries the Kubernetes API for a VirtualMachineInstance with the given name
// and returns a VMIResource containing its metadata.
// Returns:
//   - (*VMIResource, nil) if the VMI is found
//   - (nil, error) if there was an error querying the API or VMI not found
func GetVMIResourceByName(ctx context.Context, virtClient kubecli.KubevirtClient, namespace, vmiName string) (*VMIResource, error) {
	// Get the VMI
	vmi, err := virtClient.VirtualMachineInstance(namespace).Get(ctx, vmiName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get VMI %s in namespace %s: %w", vmiName, namespace, err)
	}

	return &VMIResource{
		Name:              vmi.Name,
		Namespace:         vmi.Namespace,
		UID:               string(vmi.UID),
		CreationTimestamp: vmi.CreationTimestamp,
		DeletionTimestamp: vmi.DeletionTimestamp,
	}, nil
}
