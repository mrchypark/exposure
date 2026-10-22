package operation

import (
	"reflect"
	"testing"
)

func TestPlantGetDescriptorIsTheOnlyRegisteredPatchDataOperation(t *testing.T) {
	descriptor, ok := Lookup(PlantGetID)
	if !ok {
		t.Fatal("plant.get is not registered")
	}
	if descriptor.ID != PlantGetID || descriptor.Version != 1 || descriptor.Semantics != Read ||
		descriptor.ProviderID != "patch-data" || descriptor.ActionID != "patch-data.plant.read" ||
		descriptor.ResourceType != "plant" || descriptor.ContractDigest != PlantGetContractDigest ||
		!IsPatchDataPlantRead(descriptor.Executor) {
		t.Fatalf("descriptor=%#v", descriptor)
	}
	for _, id := range []string{"", "plant.list", "plant.search", "plant.create", "plant.update", "plant.delete", "records.get"} {
		if descriptor, ok := Lookup(id); ok {
			t.Fatalf("unregistered operation %q resolved to %#v", id, descriptor)
		}
	}
}

func TestResolveBindsEveryTypedFieldAndRejectsProvisionalOperations(t *testing.T) {
	request := Request{
		OperationID: PlantGetID, OperationVersion: 1,
		ContractDigest: PlantGetContractDigest, ResourceType: "plant", ResourceID: "plant-a",
	}
	if descriptor, err := Resolve(request); err != nil || descriptor.ID != PlantGetID {
		t.Fatalf("resolve=(%#v,%v)", descriptor, err)
	}
	changes := []func(*Request){
		func(r *Request) { r.OperationID = "patch-data.organizations.list" },
		func(r *Request) { r.OperationVersion++ },
		func(r *Request) { r.ContractDigest = "sha256:invalid" },
		func(r *Request) { r.ResourceType = "organization" },
		func(r *Request) { r.ResourceID = "" },
		func(r *Request) { r.ResourceID = " plant-a" },
		func(r *Request) { r.ResourceID = "plant-a\n" },
	}
	for _, change := range changes {
		changed := request
		change(&changed)
		if descriptor, err := Resolve(changed); err == nil {
			t.Fatalf("changed request resolved to %#v", descriptor)
		}
	}
}

func TestRequestHasNoCallerSelectedBackendOrPocketBaseSelectors(t *testing.T) {
	fieldNames := map[string]bool{}
	typeOf := reflect.TypeOf(Request{})
	for i := 0; i < typeOf.NumField(); i++ {
		fieldNames[typeOf.Field(i).Name] = true
	}
	for _, forbidden := range []string{"Backend", "URL", "Path", "Method", "Query", "Filter", "Fields", "Expand", "Projection", "Schema"} {
		if fieldNames[forbidden] {
			t.Fatalf("caller-selected field %s exists", forbidden)
		}
	}
}

func TestDescriptorValuesCannotMutateTheRegisteredMapping(t *testing.T) {
	first, _ := Lookup(PlantGetID)
	first.ActionID = "attacker.action"
	second, _ := Lookup(PlantGetID)
	if second.ActionID != "patch-data.plant.read" {
		t.Fatalf("registered mapping mutated: %#v", second)
	}
}
