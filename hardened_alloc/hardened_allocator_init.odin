package hardened_alloc

import "core:crypto"

@(require_results)
hardened_allocator_init_zones :: proc(s: ^Hardened_Allocator) -> Allocator_Error {
	zerr: Allocator_Error
	s.metadata.zones, zerr = hardened_allocator_alloc_slice(
		^Hardened_Allocator_Zone,
		s.metadata.type_bucket_count,
	)
	if zerr != nil {
		return zerr
	}

	for &zone, index in s.metadata.zones {
		zaerr := hardened_allocator_alloc_zone(s, &zone, index)
		if zaerr != nil {
			return zaerr
		}

	}

	return nil
}

@(require_results)
hardened_allocator_init_metadata :: proc(
	s: ^Hardened_Allocator,
	type_bucket_count: int,
	size_class_count: int,
	quarantine_size: int,
	type_policy: Type_Class_Policy,
	validate_allocator: bool,
	manual_type_registry: Manual_Type_Registry = {fallback_class = .Opaque},
) -> Allocator_Error {
	mraw, err := _request_memory(size_of(Hardened_Allocator_Metadata))
	if err != nil {
		return err
	}

	s.metadata = cast(^Hardened_Allocator_Metadata)raw_data(mraw)

	sraw, serr := _request_memory(size_of(Hardened_Allocator_Secrets))
	if serr != nil {
		return err
	}
	s.metadata.secrets = cast(^Hardened_Allocator_Secrets)raw_data(sraw)
	hardened_allocator_init_secrets(s.metadata.secrets)
	s.metadata.secrets.validate_allocator = validate_allocator

	s.metadata.type_class_policy = type_policy
	s.metadata.size_class_count = size_class_count
	s.metadata.quarantine_size = quarantine_size

	switch type_policy {
	case .Randomized_Type_Signature:
		seed_bytes: [8]u8
		crypto.rand_bytes(seed_bytes[:])
		s.metadata.secrets.type_class_seed = transmute(u64)seed_bytes
		fallthrough

	case .Type_Signature:
		s.metadata.type_bucket_count = type_bucket_count

	case .Manual_Registry:
		if len(manual_type_registry.type_entries) < 1 {
			return .Invalid_Argument
		}
		s.metadata.manual_type_registry.fallback_class = manual_type_registry.fallback_class
		s.metadata.manual_type_registry.use_fallback_class =
			manual_type_registry.use_fallback_class
		mtrerr: Allocator_Error
		s.metadata.manual_type_registry.type_entries, mtrerr = hardened_allocator_alloc_slice(
			Manual_Type_Entry,
			len(manual_type_registry.type_entries),
		)
		if mtrerr != nil {
			return mtrerr
		}

		copy(s.metadata.manual_type_registry.type_entries, manual_type_registry.type_entries)
		s.metadata.type_bucket_count = len(Type_Class)
	}

	zerr := hardened_allocator_init_zones(s)
	if zerr != nil {
		return zerr
	}

	hardened_allocator_tag_metadata(s.metadata, s.metadata.secrets)

	return nil
}

hardened_allocator_init :: proc(
	s: ^Hardened_Allocator,
	type_bucket_count := TYPE_BUCKET_COUNT,
	size_class_count := SIZE_CLASS_COUNT,
	quarantine_size := DEFAULT_QUARANTINE_SIZE,
	type_policy := Type_Class_Policy.Randomized_Type_Signature,
	validate_allocator := true,
	manual_type_registry: Manual_Type_Registry = {fallback_class = .Opaque},
	loc := #caller_location,
) -> Allocator_Error {
	if type_bucket_count < 1 || size_class_count < 1 || quarantine_size < 1 {
		return .Invalid_Argument
	}

	err := hardened_allocator_init_metadata(
		s,
		type_bucket_count,
		size_class_count,
		quarantine_size,
		type_policy,
		validate_allocator,
		manual_type_registry,
	)

	if err == nil {
		s.initialized = true
	}

	return err
}
