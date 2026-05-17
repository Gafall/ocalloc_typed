package hardened_alloc

import "base:runtime"
import "core:reflect"

Type_Signature :: struct {
	hash:     u64,
	features: bit_set[Signature_Feature],
	index:    int,
}

Signature_Token :: enum {
	Data,
	Buffer,
	Pointer,
	Procedure,
	Opaque,
	Array_Begin,
	Array_End,
	Struct_Begin,
	Struct_End,
	Truncated,
}

Signature_Feature :: enum {
	Is_Pointer,
	Is_Procedure,
	Is_Buffer,
	Is_Opaque,
	Is_Array,
	Is_Struct,
	Is_Data,
}

hardened_allocator_determine_type_signature :: proc(
	s: ^Hardened_Allocator,
	$T: typeid,
) -> Type_Signature {
	sig := Type_Signature{}

	hardened_allocator_generate_signature(T, &sig, 0)

	sig.hash = sig.hash ~ s.metadata.secrets.type_class_seed
	sig.index = int(sig.hash % u64(s.metadata.type_bucket_count))

	return sig
}

hardened_allocator_generate_signature :: proc(T: typeid, sig: ^Type_Signature, depth: int) {
	if depth >= MAX_RECURSION_DEPTH {
		sig.features += {.Is_Opaque}
		hash_add_token(&sig.hash, .Opaque)
		hash_add_token(&sig.hash, .Truncated)
		return
	}

	info := type_info_of(T)
	base := reflect.type_info_base(info)

	hash_add_int(&sig.hash, base.size)

	if reflect.is_procedure(base) {
		if depth == 0 do sig.features += {.Is_Procedure}
		hash_add_token(&sig.hash, .Procedure)
		return
	}

	if reflect.is_pointer(base) || reflect.is_multi_pointer(base) || reflect.is_soa_pointer(base) {
		if depth == 0 do sig.features += {.Is_Pointer}
		hash_add_token(&sig.hash, .Pointer)
		return
	}

	if reflect.is_string(base) {
		if depth == 0 do sig.features += {.Is_Buffer}
		hash_add_token(&sig.hash, .Buffer)
		return
	}

	if reflect.is_slice(base) || reflect.is_dynamic_array(base) {
		if depth == 0 {
			sig.features += {.Is_Pointer}
			sig.features += {.Is_Buffer}
		}

		hash_add_token(&sig.hash, .Pointer)
		hash_add_token(&sig.hash, .Buffer)
		return
	}
	if reflect.is_any(base) || reflect.is_dynamic_map(base) {
		if depth == 0 {
			sig.features += {.Is_Pointer}
			sig.features += {.Is_Opaque}
		}

		hash_add_token(&sig.hash, .Pointer)
		hash_add_token(&sig.hash, .Opaque)
		return
	}

	if reflect.is_union(base) || reflect.is_raw_union(base) {
		if depth == 0 do sig.features += {.Is_Opaque}
		hash_add_token(&sig.hash, .Opaque)
		return
	}

	if reflect.is_array(base) ||
	   reflect.is_enumerated_array(base) ||
	   reflect.is_fixed_capacity_dynamic_array(base) {
		if depth == 0 do sig.features += {.Is_Array}

		hash_add_token(&sig.hash, .Array_Begin)
		elem_type := reflect.typeid_elem(T)
		elem_info := type_info_of(elem_type)
		elem_base := reflect.type_info_base(elem_info)

		#partial switch var in elem_base.variant {
		case runtime.Type_Info_Array:
			hash_add_int(&sig.hash, var.count)
		case runtime.Type_Info_Enumerated_Array:
			hash_add_int(&sig.hash, var.count)
		case runtime.Type_Info_Fixed_Capacity_Dynamic_Array:
			hash_add_int(&sig.hash, var.capacity)
		}

		if reflect.is_byte(elem_base) {
			if depth == 0 do sig.features += {.Is_Buffer}
			hash_add_token(&sig.hash, .Buffer)
		} else {
			hardened_allocator_generate_signature(elem_type, sig, depth + 1)
		}

		hash_add_token(&sig.hash, .Array_End)
		return
	}

	if reflect.is_struct(base) {
		if depth == 0 do sig.features += {.Is_Struct}

		hash_add_token(&sig.hash, .Struct_Begin)
		field_types := reflect.struct_field_types(T)

		for field_info in field_types {
			hardened_allocator_generate_signature(field_info.id, sig, depth + 1)
		}

		hash_add_token(&sig.hash, .Struct_End)
		return
	}

	hash_add_token(&sig.hash, .Data)
	if depth == 0 do sig.features += {.Is_Data}

	return
}


hardened_allocator_manual_registry_lookup :: proc(
	s: ^Hardened_Allocator,
	id: typeid,
) -> (
	Type_Class,
	bool,
) {
	for entry in s.metadata.manual_type_registry.type_entries {
		if entry.id == id {
			return entry.class, true
		}
	}

	if s.metadata.manual_type_registry.use_fallback_class {
		return s.metadata.manual_type_registry.fallback_class, true
	}

	return nil, false
}
