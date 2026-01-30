// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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

package ipam

import (
	"context"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// ipam.Interface has methods to perform IP address management.
type Interface interface {
	// AssignIP assigns the provided IP address to the provided host.  The IP address
	// must fall within a configured pool.  AssignIP will claim block affinity as needed
	// in order to satisfy the assignment.  An error will be returned if the IP address
	// is already assigned, or if StrictAffinity is enabled and the address is within
	// a block that does not have affinity for the given host.
	AssignIP(ctx context.Context, args AssignIPArgs) error

	// AutoAssign automatically assigns one or more IP addresses as specified by the
	// provided AutoAssignArgs.  AutoAssign returns the list of the assigned IPv4 addresses,
	// and the list of the assigned IPv6 addresses in IPNet format.
	// The returned IPNet represents the allocation block from which the IP was allocated,
	// which is useful for dataplanes that need to know the subnet (such as Windows).
	//
	// In case of error, returns the IPs allocated so far along with the error.
	AutoAssign(ctx context.Context, args AutoAssignArgs) (*IPAMAssignments, *IPAMAssignments, error)

	// ReleaseIPs releases any of the given IP addresses that are currently assigned,
	// so that they are available to be used in another assignment.
	ReleaseIPs(ctx context.Context, ips ...ReleaseOptions) ([]cnet.IP, []ReleaseOptions, error)

	// GetAssignmentAttributes returns the attributes stored with the given IP address
	// for both ActiveOwnerAttrs and AlternateOwnerAttrs, as well as the handle used
	// for assignment (if any). This provides an atomic snapshot of both attributes.
	GetAssignmentAttributes(ctx context.Context, addr cnet.IP) (activeAttrs map[string]string, alternateAttrs map[string]string, handle *string, err error)

	// IPsByHandle returns a list of all IP addresses that have been
	// assigned using the provided handle.
	IPsByHandle(ctx context.Context, handleID string) ([]cnet.IP, error)

	// ReleaseByHandle releases all IP addresses that have been assigned
	// using the provided handle.  Returns an error if no addresses
	// are assigned with the given handle.
	ReleaseByHandle(ctx context.Context, handleID string) error

	// ClaimAffinity claims affinity to the given host for all blocks
	// within the given CIDR.  The given CIDR must fall within a configured
	// pool. If an empty string is passed as the host, then the value returned by os.Hostname is used.
	ClaimAffinity(ctx context.Context, cidr cnet.IPNet, affinityCfg AffinityConfig) ([]cnet.IPNet, []cnet.IPNet, error)

	// ReleaseAffinity releases affinity for all blocks within the given CIDR
	// on the given host.  If an empty string is passed as the host, then the
	// value returned by os.Hostname will be used. If mustBeEmpty is true, then an error
	// will be returned if any blocks within the CIDR are not empty - in this case, this
	// function may release some but not all blocks within the given CIDR.
	ReleaseAffinity(ctx context.Context, cidr cnet.IPNet, host string, mustBeEmpty bool) error

	// ReleaseHostAffinities releases affinity for all blocks that are affine
	// to the given host.  If an empty string is passed as the host, the value returned by
	// os.Hostname will be used. If mustBeEmpty is true, then an error
	// will be returned if any blocks within the CIDR are not empty - in this case, this
	// function may release some but not all blocks attached to this host.
	ReleaseHostAffinities(ctx context.Context, affinityCfg AffinityConfig, mustBeEmpty bool) error

	// ReleasePoolAffinities releases affinity for all blocks within
	// the specified pool across all hosts.
	ReleasePoolAffinities(ctx context.Context, pool cnet.IPNet) error

	// ReleaseBlockAffinity releases the affinity of the exact block provided.
	ReleaseBlockAffinity(ctx context.Context, block *model.AllocationBlock, mustBeEmpty bool) error

	// GetIPAMConfig returns the global IPAM configuration.  If no IPAM configuration
	// has been set, returns a default configuration with StrictAffinity disabled
	// and AutoAllocateBlocks enabled.
	GetIPAMConfig(ctx context.Context) (*IPAMConfig, error)

	// SetIPAMConfig sets global IPAM configuration.  This can only
	// be done when there are no allocated blocks and IP addresses.
	SetIPAMConfig(ctx context.Context, cfg IPAMConfig) error

	// RemoveIPAMHost releases affinity for all blocks on the given host,
	// and removes all host-specific IPAM data from the datastore.
	// RemoveIPAMHost does not release any IP addresses claimed on the given host.
	// If an empty string is passed as the host then the value returned by os.Hostname is used.
	RemoveIPAMHost(ctx context.Context, affinityCfg AffinityConfig) error

	// GetUtilization returns IP utilization info for the specified pools, or for all pools.
	GetUtilization(ctx context.Context, args GetUtilizationArgs) ([]*PoolUtilization, error)

	// EnsureBlock returns single IPv4/IPv6 IPAM block for a host as specified by the provided BlockArgs.
	// If there is no block allocated already for this host, allocate one and return its CIDR.
	// Otherwise, return the CIDR of the IPAM block allocated for this host.
	// It returns IPv4, IPv6 block CIDR and any error encountered.
	EnsureBlock(ctx context.Context, args BlockArgs) (*cnet.IPNet, *cnet.IPNet, error)

	// UpgradeHost checks the resources related to the given node and, if it
	// finds any that are in older formats, upgrades them.  It is idempotent.
	UpgradeHost(ctx context.Context, nodeName string) error

	// SetOwnerAttributes sets ActiveOwnerAttrs and/or AlternateOwnerAttrs for an IP atomically.
	// This is used for VMI live migration scenarios to manage pod ownership attributes.
	//
	// Parameters:
	//   - attrsActiveOwner: Attributes to set for ActiveOwnerAttrs.
	//     If nil, ActiveOwnerAttrs is not modified.
	//     If an empty map (map[string]string{}), ActiveOwnerAttrs is cleared (set to nil).
	//
	//   - attrsAlternateOwner: Attributes to set for AlternateOwnerAttrs.
	//     If nil, AlternateOwnerAttrs is not modified.
	//     If an empty map (map[string]string{}), AlternateOwnerAttrs is cleared (set to nil).
	//
	//   - expectedActiveOwner:
	//     If non-nil, verifies current ActiveOwnerAttrs matches before setting.
	//        Prevents overwriting attributes that belong to a different pod.
	//     If an AttributeOwner with empty namespace and name is passed,
	//        verifies that ActiveOwnerAttrs is empty (nil or empty map) before setting.
	//
	//  - expectedAlternateOwner:
	//     If non-nil, verifies current AlternateOwnerAttrs matches before setting.
	//        Prevents overwriting attributes that belong to a different pod.
	//     If an AttributeOwner with empty namespace and name is passed,
	//        verifies that AlternateOwnerAttrs is empty (nil or empty map) before setting.
	//
	// Use cases:
	//   - Set AlternateOwnerAttrs only: attrsActiveOwner=nil, attrsAlternateOwner=<target pod attrs>
	//   - Clear ActiveOwnerAttrs: attrsActiveOwner=map[string]string{}, attrsAlternateOwner=nil
	//   - Swap attributes: attrsActiveOwner=<current alternate>, attrsAlternateOwner=<current active>
	//   - Set both: attrsActiveOwner=<new active>, attrsAlternateOwner=<new alternate>
	SetOwnerAttributes(ctx context.Context, ip cnet.IP, handleID string, attrsActiveOwner, attrsAlternateOwner map[string]string, expectedActiveOwner, expectedAlternateOwner *AttributeOwner) error
}
