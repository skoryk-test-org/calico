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
// KubeVirt virt-launcher pods are identified by their ownerReferences, which contain a
// reference to the VirtualMachineInstance that owns the pod. This is the Kubernetes-native
// and most reliable way to determine VMI ownership.
//
// Example pod ownerReferences for a virt-launcher pod:
//
//	ownerReferences:
//	  - apiVersion: kubevirt.io/v1
//	    kind: VirtualMachineInstance
//	    name: vm1
//	    uid: d2ad3ee8-1082-4d61-8202-dbc2432cdd88  # VMI UID
//	    controller: true
//
// During live migration, migration target pods have an additional label:
//
//	labels:
//	  kubevirt.io/migrationJobUID: 122eae59-b197-42c1-a58d-67248f8e5be9  # ONLY ON TARGET POD
//
// Migration scenario:
//   - Source pod: Owned by VMI (via ownerReferences), does NOT have migrationJobUID label
//   - Target pod: Owned by same VMI (via ownerReferences), HAS migrationJobUID label
//
// The VMI UID from ownerReferences remains stable across pod recreations and migrations,
// making it suitable as a basis for IPAM handle IDs to ensure IP address persistence.
package kubevirt

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubevirtv1 "kubevirt.io/api/core/v1"
)

// KubeVirt label keys
const (
	// LabelKubeVirtMigrationJobUID is only present on migration target pods
	// Value from kubevirtv1.MigrationJobLabel
	LabelKubeVirtMigrationJobUID = kubevirtv1.MigrationJobLabel

	// VMI API Group, Version, and Resource for dynamic client
	VMIGroup   = "kubevirt.io"
	VMIVersion = "v1"
)

// PodVMIInfo contains KubeVirt VMI-related information extracted from a pod's
// ownerReferences and verified against the actual VMI resource via the Kubernetes API.
type PodVMIInfo struct {
	*VMIResource // Embedded: Name, Namespace, UID, DeletionTimestamp, CreationTimestamp

	// MigrationJobUID is only present on migration target pods
	// (extracted from the kubevirt.io/migrationJobUID label)
	MigrationJobUID string

	// isVirtLauncher indicates if this pod is owned by a VMI (virt-launcher pod)
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
	// ActivePods is a mapping of pod UID to node name
	// Multiple pods can be active during migration (source and target)
	ActivePods map[string]string
	// MigrationUID is the UID of the active migration (if any)
	// Empty string if no migration is in progress
	MigrationUID string
	// MigrationTargetPod is the name of the target pod during migration
	// Empty string if no migration is in progress
	MigrationTargetPod string
	// MigrationSourcePod is the name of the source pod during migration
	// Empty string if no migration is in progress
	MigrationSourcePod string
}

// IsDeletionInProgress returns true if the VMI has a deletion timestamp set
func (v *VMIResource) IsDeletionInProgress() bool {
	return v.DeletionTimestamp != nil && !v.DeletionTimestamp.IsZero()
}

// GetPodVMIInfo determines if a pod is a KubeVirt virt-launcher pod by checking its
// ownerReferences for a VirtualMachineInstance owner, then verifies it against the
// actual VMI resource via the Kubernetes API.
// Returns:
//   - (*PodVMIInfo, nil) if the pod is a valid virt-launcher pod with verified VMI
//   - (nil, nil) if the pod is not owned by a VMI (not a virt-launcher pod)
//   - (nil, error) if verification fails or VMI query fails
func GetPodVMIInfo(pod *corev1.Pod, virtClient VirtClientInterface) (*PodVMIInfo, error) {
	if pod == nil {
		return nil, nil
	}

	// Check ownerReferences to find VMI owner
	// KubeVirt sets the VirtualMachineInstance as the controller owner of virt-launcher pods
	var vmiOwner *metav1.OwnerReference
	for i := range pod.OwnerReferences {
		owner := &pod.OwnerReferences[i]
		if owner.APIVersion == VMIGroup+"/"+VMIVersion &&
			owner.Kind == "VirtualMachineInstance" &&
			owner.Controller != nil && *owner.Controller {
			vmiOwner = owner
			break
		}
	}

	if vmiOwner == nil {
		// Not a virt-launcher pod (no VMI owner)
		return nil, nil
	}

	// Extract VMI name and UID from ownerReference
	vmiName := vmiOwner.Name
	vmiUID := string(vmiOwner.UID)

	if vmiName == "" || vmiUID == "" {
		return nil, fmt.Errorf("pod %s/%s has invalid VMI ownerReference: name=%q uid=%q",
			pod.Namespace, pod.Name, vmiName, vmiUID)
	}

	// Query the actual VMI resource to verify and get complete information
	vmiResource, err := GetVMIResourceByName(
		context.Background(),
		virtClient,
		pod.Namespace,
		vmiName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query VMI resource %s/%s: %w",
			pod.Namespace, vmiName, err)
	}

	// Verify that the VMI UID from ownerReference matches the actual VMI resource
	if vmiResource.UID != vmiUID {
		return nil, fmt.Errorf("VMI UID mismatch: pod ownerReference has %s but VMI resource has %s",
			vmiUID, vmiResource.UID)
	}

	// Check for migration target label (only label we trust for migration state)
	// This label is only present on migration target pods during live migration
	migrationUIDFromLabel := ""
	if pod.Labels != nil {
		if migrationUID, ok := pod.Labels[LabelKubeVirtMigrationJobUID]; ok {
			migrationUIDFromLabel = migrationUID
		}
	}

	// Create PodVMIInfo with embedded VMIResource
	info := &PodVMIInfo{
		VMIResource:     vmiResource,
		isVirtLauncher:  true,
		MigrationJobUID: migrationUIDFromLabel,
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

// GetVMIName returns the VMI name (from embedded VMIResource)
func (v *PodVMIInfo) GetVMIName() string {
	if v.VMIResource == nil {
		return ""
	}
	return v.VMIResource.Name
}

// GetVMIUID returns the VMI UID (from embedded VMIResource)
func (v *PodVMIInfo) GetVMIUID() string {
	if v.VMIResource == nil {
		return ""
	}
	return v.VMIResource.UID
}

// GetVMIMigrationUID returns the migration job UID.
// Returns empty string if this is not a migration target pod.
func (v *PodVMIInfo) GetVMIMigrationUID() string {
	return v.MigrationJobUID
}

// verifyVMIOwnership validates that the pod is actually owned by the VMI with the given UID.
// This prevents users from spoofing virt-launcher behavior by adding labels to normal pods.
// KubeVirt sets the VirtualMachineInstance as the controller owner of virt-launcher pods.
// GetVMIResourceByUID queries the Kubernetes API for a VirtualMachineInstance with the given UID
// and returns a VMIResource containing its metadata.
// Returns:
//   - (*VMIResource, nil) if the VMI is found
//   - (nil, error) if there was an error querying the API or VMI not found
func GetVMIResourceByUID(ctx context.Context, virtClient VirtClientInterface, namespace, vmiUID string) (*VMIResource, error) {
	// List VMIs in the namespace
	vmiList, err := virtClient.VirtualMachineInstance(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list VMIs in namespace %s: %w", namespace, err)
	}

	// Find the VMI with matching UID
	for _, vmi := range vmiList.Items {
		if string(vmi.UID) == vmiUID {
			// Convert ActivePods from map[types.UID]string to map[string]string
			activePods := make(map[string]string)
			if vmi.Status.ActivePods != nil {
				for podUID, nodeName := range vmi.Status.ActivePods {
					activePods[string(podUID)] = nodeName
				}
			}

			// Extract migration information if migration is in progress
			migrationUID := ""
			migrationTargetPod := ""
			migrationSourcePod := ""
			if vmi.Status.MigrationState != nil {
				migrationUID = string(vmi.Status.MigrationState.MigrationUID)
				migrationTargetPod = vmi.Status.MigrationState.TargetPod
				migrationSourcePod = vmi.Status.MigrationState.SourcePod
			}

			// Found the VMI, populate VMIResource
			return &VMIResource{
				Name:               vmi.Name,
				Namespace:          vmi.Namespace,
				UID:                string(vmi.UID),
				DeletionTimestamp:  vmi.DeletionTimestamp,
				ActivePods:         activePods,
				MigrationUID:       migrationUID,
				MigrationTargetPod: migrationTargetPod,
				MigrationSourcePod: migrationSourcePod,
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
func GetVMIResourceByName(ctx context.Context, virtClient VirtClientInterface, namespace, vmiName string) (*VMIResource, error) {
	// Get the VMI
	vmi, err := virtClient.VirtualMachineInstance(namespace).Get(ctx, vmiName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get VMI %s in namespace %s: %w", vmiName, namespace, err)
	}

	// Convert ActivePods from map[types.UID]string to map[string]string
	activePods := make(map[string]string)
	if vmi.Status.ActivePods != nil {
		for podUID, nodeName := range vmi.Status.ActivePods {
			activePods[string(podUID)] = nodeName
		}
	}

	// Extract migration information if migration is in progress
	migrationUID := ""
	migrationTargetPod := ""
	migrationSourcePod := ""
	if vmi.Status.MigrationState != nil {
		migrationUID = string(vmi.Status.MigrationState.MigrationUID)
		migrationTargetPod = vmi.Status.MigrationState.TargetPod
		migrationSourcePod = vmi.Status.MigrationState.SourcePod
	}

	return &VMIResource{
		Name:               vmi.Name,
		Namespace:          vmi.Namespace,
		UID:                string(vmi.UID),
		DeletionTimestamp:  vmi.DeletionTimestamp,
		ActivePods:         activePods,
		MigrationUID:       migrationUID,
		MigrationTargetPod: migrationTargetPod,
		MigrationSourcePod: migrationSourcePod,
	}, nil
}
