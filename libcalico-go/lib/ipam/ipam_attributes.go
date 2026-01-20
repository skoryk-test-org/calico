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

package ipam

import (
	"context"
	"errors"
	"fmt"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	log "github.com/sirupsen/logrus"
)

// GetAssignmentAttributes returns the attributes stored with the given IP address
// for the specified owner type (Active or Alternate), as well as the handle used
// for assignment (if any).
func (c ipamClient) GetAssignmentAttributes(ctx context.Context, addr cnet.IP, attrType OwnerAttributeType) (map[string]string, *string, error) {
	pool, err := c.blockReaderWriter.getPoolForIP(ctx, addr, nil)
	if err != nil {
		return nil, nil, err
	}
	if pool == nil {
		log.Errorf("Error reading pool for %s", addr.String())
		return nil, nil, cerrors.ErrorResourceDoesNotExist{Identifier: addr.String(), Err: errors.New("No valid IPPool")}
	}
	blockCIDR := getBlockCIDRForAddress(addr, pool)
	obj, err := c.blockReaderWriter.queryBlock(ctx, blockCIDR, "")
	if err != nil {
		log.Errorf("Error reading block %s: %v", blockCIDR, err)
		return nil, nil, err
	}
	block := allocationBlock{obj.Value.(*model.AllocationBlock)}
	attrs, err := block.attributesForIP(addr, attrType)
	if err != nil {
		return nil, nil, err
	}
	handle, err := block.handleForIP(addr)
	if err != nil {
		return nil, nil, err
	}
	return attrs, handle, nil
}

// ClearAttribute clears the specified attribute (Active or Alternate) for an IP
// without releasing the IP itself.
func (c ipamClient) ClearAttribute(ctx context.Context, ip cnet.IP, handleID string, attrType OwnerAttributeType) error {
	logCtx := log.WithFields(log.Fields{
		"ip":       ip,
		"handleID": handleID,
		"attrType": attrType,
	})
	logCtx.Info("Clearing IP attribute")

	// Find the pool for this IP.
	pool, err := c.blockReaderWriter.getPoolForIP(ctx, ip, nil)
	if err != nil {
		return err
	}
	if pool == nil {
		return fmt.Errorf("the provided IP address %s is not in a configured pool", ip)
	}

	// Get the block CIDR for this IP.
	blockCIDR := getBlockCIDRForAddress(ip, pool)
	logCtx.Debugf("IP %s is in block '%s'", ip, blockCIDR)

	// Retry loop for CAS operations.
	for i := 0; i < datastoreRetries; i++ {
		// Get the allocation block.
		obj, err := c.blockReaderWriter.queryBlock(ctx, blockCIDR, "")
		if err != nil {
			logCtx.WithError(err).Error("Error getting block")
			return err
		}

		// Clear the attribute in the block.
		block := allocationBlock{obj.Value.(*model.AllocationBlock)}
		err = block.clearAttribute(ip, handleID, attrType)
		if err != nil {
			logCtx.WithError(err).Error("Failed to clear attribute")
			return err
		}

		// Update the block using CAS.
		_, err = c.blockReaderWriter.updateBlock(ctx, obj)
		if err != nil {
			if _, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
				logCtx.WithError(err).Debug("CAS error clearing attribute - retry")
				continue
			}
			logCtx.WithError(err).Error("Failed to update block")
			return err
		}

		logCtx.Info("Successfully cleared IP attribute")
		return nil
	}

	return fmt.Errorf("max retries hit - excessive concurrent IPAM requests")
}

// SwapAttributes swaps ActiveOwnerAttrs and AlternateOwnerAttrs for an IP.
func (c ipamClient) SwapAttributes(ctx context.Context, ip cnet.IP, handleID string) error {
	logCtx := log.WithFields(log.Fields{
		"ip":       ip,
		"handleID": handleID,
	})
	logCtx.Info("Swapping IP attributes")

	// Find the pool for this IP.
	pool, err := c.blockReaderWriter.getPoolForIP(ctx, ip, nil)
	if err != nil {
		return err
	}
	if pool == nil {
		return fmt.Errorf("the provided IP address %s is not in a configured pool", ip)
	}

	// Get the block CIDR for this IP.
	blockCIDR := getBlockCIDRForAddress(ip, pool)
	logCtx.Debugf("IP %s is in block '%s'", ip, blockCIDR)

	// Retry loop for CAS operations.
	for i := 0; i < datastoreRetries; i++ {
		// Get the allocation block.
		obj, err := c.blockReaderWriter.queryBlock(ctx, blockCIDR, "")
		if err != nil {
			logCtx.WithError(err).Error("Error getting block")
			return err
		}

		// Swap the attributes in the block.
		block := allocationBlock{obj.Value.(*model.AllocationBlock)}
		err = block.swapAttributes(ip, handleID)
		if err != nil {
			logCtx.WithError(err).Error("Failed to swap attributes")
			return err
		}

		// Update the block using CAS.
		_, err = c.blockReaderWriter.updateBlock(ctx, obj)
		if err != nil {
			if _, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
				logCtx.WithError(err).Debug("CAS error swapping attributes - retry")
				continue
			}
			logCtx.WithError(err).Error("Failed to update block")
			return err
		}

		logCtx.Info("Successfully swapped IP attributes")
		return nil
	}

	return fmt.Errorf("max retries hit - excessive concurrent IPAM requests")
}
