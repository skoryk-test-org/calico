# KubeVirt Client Testing

This package provides a testable interface for KubeVirt client operations, allowing you to write tests without requiring a real KubeVirt cluster.

## Architecture

### Interfaces

- **`VirtClientInterface`**: The main interface that wraps KubeVirt client functionality
- **`VMIInterface`**: Interface for VirtualMachineInstance operations (Get, List)

### Production Implementation

- **`virtClientAdapter`**: Wraps the real `kubecli.KubevirtClient` to implement our interface
- **`NewVirtClientAdapter()`**: Factory function to create the adapter

### Test Implementation

- **`FakeVirtClient`**: In-memory fake implementation for testing
- **`NewFakeVirtClient()`**: Factory function to create a fake client
- **`VMIBuilder`**: Fluent builder for constructing VMI test objects

## Usage in Production Code

```go
import (
    "github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
    "kubevirt.io/client-go/kubecli"
)

// Create real KubeVirt client
realClient, err := kubecli.GetKubevirtClientFromRESTConfig(config)
if err != nil {
    return err
}

// Wrap with our interface
virtClient := kubevirt.NewVirtClientAdapter(realClient)

// Use the interface
vmiInfo, err := kubevirt.GetPodVMIInfo(pod, virtClient)
```

## Usage in Tests

```go
import (
    "testing"
    "github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
)

func TestMyFunction(t *testing.T) {
    // Create fake client
    fakeClient := kubevirt.NewFakeVirtClient()
    
    // Build and add a VMI
    vmi := kubevirt.NewVMIBuilder("my-vmi", "default", "vmi-uid-123").
        WithActivePod("pod-uid-456", "node1").
        Build()
    fakeClient.AddVMI(vmi)
    
    // Use in your code
    vmiInfo, err := kubevirt.GetPodVMIInfo(pod, fakeClient)
    
    // Assert results
    if vmiInfo == nil {
        t.Error("Expected VMI info")
    }
}
```

## Testing Migration Scenarios

### Source Pod (no migration label)

```go
vmi := kubevirt.NewVMIBuilder("my-vmi", "default", "vmi-123").
    WithActivePod("source-pod-uid", "node1").
    Build()
fakeClient.AddVMI(vmi)

sourcePod := &corev1.Pod{
    ObjectMeta: metav1.ObjectMeta{
        Name: "virt-launcher-my-vmi-abc",
        UID:  "source-pod-uid",
        OwnerReferences: []metav1.OwnerReference{{
            APIVersion: "kubevirt.io/v1",
            Kind:       "VirtualMachineInstance",
            Name:       "my-vmi",
            UID:        "vmi-123",
            Controller: &trueVal,
        }},
    },
}

info, _ := kubevirt.GetPodVMIInfo(sourcePod, fakeClient)
// info.IsMigrationTarget() == false
```

### Target Pod (with migration label)

```go
vmi := kubevirt.NewVMIBuilder("my-vmi", "default", "vmi-123").
    WithActivePod("source-pod-uid", "node1").
    WithActivePod("target-pod-uid", "node2").
    WithMigration("migration-uid-789", "virt-launcher-my-vmi-abc", "virt-launcher-my-vmi-xyz").
    Build()
fakeClient.AddVMI(vmi)

targetPod := &corev1.Pod{
    ObjectMeta: metav1.ObjectMeta{
        Name: "virt-launcher-my-vmi-xyz",
        UID:  "target-pod-uid",
        Labels: map[string]string{
            kubevirt.LabelKubeVirtMigrationJobUID: "migration-uid-789",
        },
        OwnerReferences: []metav1.OwnerReference{{
            APIVersion: "kubevirt.io/v1",
            Kind:       "VirtualMachineInstance",
            Name:       "my-vmi",
            UID:        "vmi-123",
            Controller: &trueVal,
        }},
    },
}

info, _ := kubevirt.GetPodVMIInfo(targetPod, fakeClient)
// info.IsMigrationTarget() == true
// info.GetVMIMigrationUID() == "migration-uid-789"
```

### VMI Being Deleted

```go
now := metav1.Now()
vmi := kubevirt.NewVMIBuilder("my-vmi", "default", "vmi-123").
    WithActivePod("pod-uid-456", "node1").
    WithDeletionTimestamp(now).
    Build()
fakeClient.AddVMI(vmi)

info, _ := kubevirt.GetPodVMIInfo(pod, fakeClient)
// info.IsDeletionInProgress() == true
```

## Fake Client Methods

The `FakeVirtClient` provides additional methods for test setup:

- `AddVMI(vmi *kubevirtv1.VirtualMachineInstance)` - Add a VMI to the fake cluster
- `DeleteVMI(namespace, name string)` - Remove a VMI from the fake cluster
- `UpdateVMI(vmi *kubevirtv1.VirtualMachineInstance)` - Update an existing VMI

## VMIBuilder Methods

The fluent builder supports:

- `NewVMIBuilder(name, namespace, uid string)` - Create a new builder
- `WithActivePod(podUID, nodeName string)` - Add a pod to ActivePods
- `WithMigration(migrationUID, sourcePod, targetPod string)` - Set migration state
- `WithDeletionTimestamp(t metav1.Time)` - Mark VMI as being deleted
- `Build()` - Return the constructed VMI

## Benefits

1. **No Cluster Required**: Tests run without needing a KubeVirt cluster
2. **Fast**: In-memory operations are instant
3. **Deterministic**: Full control over VMI state
4. **Thread-Safe**: Fake client uses mutex for concurrent access
5. **Easy Setup**: Fluent builder makes test data creation simple

