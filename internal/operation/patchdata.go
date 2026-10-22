package operation

const PlantGetID = "plant.get"
const PlantGetContractDigest = "sha256:7ca72b56a8f32ab247d4d8dc936b30cedf2f9995c1ad8cc5b2f2703dc20f488d"

var patchDataPlantRead = ExecutorToken{id: 1}

func patchDataPlantGetDescriptor() Descriptor {
	return Descriptor{
		ID: PlantGetID, Version: 1, ContractDigest: PlantGetContractDigest,
		Semantics: Read, ProviderID: "patch-data", ActionID: "patch-data.plant.read",
		ResourceType: "plant", Executor: patchDataPlantRead,
	}
}

func IsPatchDataPlantRead(token ExecutorToken) bool { return token == patchDataPlantRead }
