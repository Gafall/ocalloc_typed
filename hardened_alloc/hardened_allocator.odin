package hardened_alloc

import "base:runtime"
import "core:crypto"
import "core:mem"
import "core:reflect"
import "core:slice"
import "core:sync"

// The following code is largely based on how some of the official Odin allocators
// https://github.com/odin-lang/Odin/blob/16ebdc19dd1743d8432aefa55cbc847530399d4d/core/mem/allocators.odin

typed_new :: proc(
	$T: typeid,
	alignment := align_of(T),
	allocator := context.allocator,
	loc := #caller_location,
) -> (
	^T,
	Allocator_Error,
) {
	if allocator.procedure == hardened_allocator_proc {
		raw, err := hardened_allocator_alloc(cast(^Hardened_Allocator)allocator.data, T, alignment)
		if err != nil {
			return nil, err
		}
		return cast(^T)raw, nil
	}
	return mem.new_aligned(T, alignment, allocator, loc)

}

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

Type_Class_Policy :: enum {
	Manual_Registry,
	Type_Signature,
	Randomized_Type_Signature,
}

Type_Class :: enum {
	Data, // for plain types
	Buffer, // for buffers
	Pointer_Containing, // for things that have pointers
	Procedure_Containing, // for things that have procedures
	Sensitive, // for things considered sensitive
	Opaque, // fallback for types that are hard to classify
}

Manual_Type_Entry :: struct {
	id:    typeid,
	class: Type_Class,
}

Manual_Type_Registry :: struct {
	type_entries:       []Manual_Type_Entry,
	fallback_class:     Type_Class,
	use_fallback_class: bool,
}

Hardened_Allocator_Zone :: struct {
	region_list:      ^Hardened_Allocator_Region,
	region_mutex:     sync.Mutex,
	free_lists:       []^Hardened_Allocator_Free_Block,
	free_lists_mutex: []sync.Mutex,
}

Hardened_Allocator :: struct {
	fallback_allocator: Allocator, // used for allocating regions on some OS
	metadata:           ^Hardened_Allocator_Metadata,
}

Hardened_Allocator_Metadata :: struct {
	zones:                []^Hardened_Allocator_Zone,
	type_class_policy:    Type_Class_Policy,
	manual_type_registry: Manual_Type_Registry,
	type_bucket_count:    int,
	type_class_seed:      u64,
}

Hardened_Allocator_Region :: struct {
	next:         ^Hardened_Allocator_Region,
	zone:         ^Hardened_Allocator_Zone,
	memory:       []byte,
	type_index:   int,
	usable_start: rawptr,
	usable_size:  int,
}

Hardened_Allocator_Free_Block :: struct #align (align_of(uintptr)) {
	size:   int,
	region: ^Hardened_Allocator_Region,
	next:   ^Hardened_Allocator_Free_Block,
}

Hardened_Allocator_Allocation_Header :: struct #align (align_of(uintptr)) {
	block_size:     int,
	requested_size: int,
	alignment:      int,
	padding:        int,
	sig:            Type_Signature,
	region:         ^Hardened_Allocator_Region,
}

@(require_results)
hardened_allocator :: proc(s: ^Hardened_Allocator) -> Allocator {
	return Allocator{procedure = hardened_allocator_proc, data = s}
}

@(require_results)
hardened_allocator_alloc_slice :: proc(
	$T: typeid,
	count: int,
	allocator: Allocator,
) -> (
	[]T,
	Allocator_Error,
) {
	raw, err := _request_memory(count * size_of(T), align_of(T), allocator)
	if err != nil || raw == nil {
		return nil, err
	}

	temp := slice.from_ptr(cast(^T)raw_data(raw), count)
	mem.zero_slice(temp)

	return temp, nil
}

hardened_allocator_free_slice :: proc(
	$T: typeid,
	s: []T,
	allocator: Allocator,
) -> Allocator_Error {
	if s == nil {
		return nil
	}

	raw := slice.from_ptr(cast(^u8)raw_data(s), len(s) * size_of(T))

	return _free_memory(raw, allocator)
}

hardened_allocator_determine_type_signature :: proc(
	s: ^Hardened_Allocator,
	$T: typeid,
) -> Type_Signature {
	sig := Type_Signature{}

	hardened_allocator_generate_signature(T, &sig, 0)

	sig.hash = sig.hash ~ s.metadata.type_class_seed
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

@(require_results)
hardened_allocator_alloc_zone :: proc(
	zone: ^^Hardened_Allocator_Zone,
	zone_index: int,
	allocator: Allocator,
) -> Allocator_Error {
	raw, err := _request_memory(
		size_of(Hardened_Allocator_Zone),
		align_of(Hardened_Allocator_Zone),
		allocator,
	)
	if err != nil {
		return err
	}
	zone^ = cast(^Hardened_Allocator_Zone)raw_data(raw)

	zone^.region_list = nil
	zone^.region_mutex = {}

	ferr: Allocator_Error
	zone^.free_lists, ferr = hardened_allocator_alloc_slice(
		^Hardened_Allocator_Free_Block,
		SIZE_CLASS_COUNT,
		allocator,
	)
	if ferr != nil {
		return ferr
	}

	mferr: Allocator_Error
	zone^.free_lists_mutex, mferr = hardened_allocator_alloc_slice(
		sync.Mutex,
		SIZE_CLASS_COUNT,
		allocator,
	)
	if mferr != nil {
		return mferr
	}

	return nil
}

@(require_results)
hardened_allocator_init_zones :: proc(s: ^Hardened_Allocator) -> Allocator_Error {
	zerr: Allocator_Error
	s.metadata.zones, zerr = hardened_allocator_alloc_slice(
		^Hardened_Allocator_Zone,
		s.metadata.type_bucket_count,
		s.fallback_allocator,
	)
	if zerr != nil {
		return zerr
	}

	for &zone, index in s.metadata.zones {
		zaerr := hardened_allocator_alloc_zone(&zone, index, s.fallback_allocator)
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
	type_policy: Type_Class_Policy,
	allocator: Allocator,
	manual_type_registry: Manual_Type_Registry = {fallback_class = .Opaque},
) -> Allocator_Error {
	s.fallback_allocator = allocator
	raw, err := _request_memory(
		size_of(Hardened_Allocator_Metadata),
		align_of(Hardened_Allocator_Metadata),
		allocator,
	)
	if err != nil {
		return err
	}

	s.metadata = cast(^Hardened_Allocator_Metadata)raw_data(raw)

	s.metadata.type_class_policy = type_policy

	switch type_policy {
	case .Randomized_Type_Signature:
		seed_bytes: [8]u8
		crypto.rand_bytes(seed_bytes[:])
		s.metadata.type_class_seed = transmute(u64)seed_bytes
		fallthrough

	case .Type_Signature:
		s.metadata.type_bucket_count = type_bucket_count

	case .Manual_Registry:
		if len(manual_type_registry.type_entries) < 1 {
			return .Invalid_Argument
		}
		s.metadata.manual_type_registry.fallback_class = manual_type_registry.fallback_class
		s.metadata.manual_type_registry.use_fallback_class = manual_type_registry.use_fallback_class
		mtrerr: Allocator_Error
		s.metadata.manual_type_registry.type_entries, mtrerr = hardened_allocator_alloc_slice(
			Manual_Type_Entry,
			len(manual_type_registry.type_entries),
			s.fallback_allocator,
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

	return nil
}

hardened_allocator_init :: proc(
	s: ^Hardened_Allocator,
	fallback_allocator := context.allocator,
	type_bucket_count := TYPE_BUCKET_COUNT,
	type_policy := Type_Class_Policy.Randomized_Type_Signature,
	manual_type_registry: Manual_Type_Registry = {fallback_class = .Opaque},
	loc := #caller_location,
) -> Allocator_Error {
	if type_bucket_count < 1 {
		return .Invalid_Argument
	}

	return hardened_allocator_init_metadata(s, type_bucket_count, type_policy, fallback_allocator, manual_type_registry)
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

@(require_results)
hardened_allocator_alloc :: proc(
	s: ^Hardened_Allocator,
	$T: typeid,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {	
	sig := hardened_allocator_determine_type_signature(s, T)

	if s.metadata.type_class_policy == .Manual_Registry {
		type, found := hardened_allocator_manual_registry_lookup(s, T)
		if !found {
			return nil, .Invalid_Argument
		}

		sig.index = int(type)
	}

	bytes, err := hardened_allocator_alloc_bytes(s, &sig, size_of(T), alignment, loc)

	return raw_data(bytes), err
}

@(require_results)
hardened_allocator_alloc_bytes :: proc(
	s: ^Hardened_Allocator,
	sig: ^Type_Signature,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	[]byte,
	Allocator_Error,
) {
	bytes, err := hardened_allocator_alloc_bytes_non_zeroed(s, sig, size, alignment, loc)
	if bytes != nil {
		mem.zero_slice(bytes)
	}
	return bytes, err
}

@(require_results)
hardened_allocator_alloc_non_zeroed :: proc(
	s: ^Hardened_Allocator,
	sig: ^Type_Signature,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {
	bytes, err := hardened_allocator_alloc_bytes_non_zeroed(s, sig, size, alignment, loc)
	return raw_data(bytes), err
}

hardened_allocator_destroy :: proc(s: ^Hardened_Allocator, loc := #caller_location) {
	for &zone in s.metadata.zones {
		region := zone.region_list
		for region != nil {
			next := region.next

			_free_memory(region.memory, s.fallback_allocator)
			region = next
		}

		zone.region_list = nil
		zone.region_mutex = {}
		hardened_allocator_free_slice(
			^Hardened_Allocator_Free_Block,
			zone.free_lists,
			s.fallback_allocator,
		)
		hardened_allocator_free_slice(sync.Mutex, zone.free_lists_mutex, s.fallback_allocator)

		_free_memory(
			slice.bytes_from_ptr(zone, size_of(Hardened_Allocator_Zone)),
			s.fallback_allocator,
		)
	}

	hardened_allocator_free_slice(^Hardened_Allocator_Zone, s.metadata.zones, s.fallback_allocator)

	_free_memory(
		slice.bytes_from_ptr(s.metadata, size_of(Hardened_Allocator_Metadata)),
		s.fallback_allocator,
	)

	s.fallback_allocator = {}
}

@(require_results, no_sanitize_address)
hardened_allocator_alloc_bytes_non_zeroed :: proc(
	s: ^Hardened_Allocator,
	sig: ^Type_Signature,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	[]byte,
	Allocator_Error,
) {
	if size == 0 {
		return nil, nil
	}
	if alignment <= 0 {
		return nil, .Invalid_Argument
	}

	block, prev, size_index, used_size, padding, lock := hardened_allocator_find_block(
		s,
		sig,
		size,
		alignment,
	)
	if block == nil {
		err := hardened_allocator_add_region_for_request(s, sig, size, alignment, loc)
		if err != nil {
			return nil, err
		}

		block, prev, size_index, used_size, padding, lock = hardened_allocator_find_block(
			s,
			sig,
			size,
			alignment,
		)
		if block == nil {
			return nil, .Out_Of_Memory
		}
	}

	zone := s.metadata.zones[sig.index]

	hardened_allocator_remove_free_block(s, zone, size_index, prev, block)
	sync.unlock(lock)

	region := block.region

	remaining := block.size - used_size
	min_split_size := size_of(Hardened_Allocator_Free_Block) + MIN_SPLIT_PAYLOAD

	if remaining >= min_split_size {
		block_addr := uintptr(block)
		tail_addr := block_addr + uintptr(used_size)

		tail := (^Hardened_Allocator_Free_Block)(rawptr(tail_addr))
		tail.size = remaining
		tail.region = region
		tail.next = nil

		hardened_allocator_insert_free_block(s, sig, tail)
	} else {
		used_size = block.size
	}

	block_addr := uintptr(block)
	user_addr := block_addr + uintptr(padding)

	header := (^Hardened_Allocator_Allocation_Header)(
		rawptr(user_addr - uintptr(size_of(Hardened_Allocator_Allocation_Header))),
	)

	header.block_size = used_size
	header.requested_size = size
	header.alignment = alignment
	header.padding = padding
	header.region = region
	header.sig.features = sig.features
	header.sig.hash = sig.hash
	header.sig.index = sig.index

	return mem.byte_slice(rawptr(user_addr), size), nil
}

@(no_sanitize_address)
hardened_allocator_free :: proc(
	s: ^Hardened_Allocator,
	ptr: rawptr,
	loc := #caller_location,
) -> Allocator_Error {
	if ptr == nil {
		return nil
	}

	user_addr := uintptr(ptr)
	header_addr := user_addr - uintptr(size_of(Hardened_Allocator_Allocation_Header))
	header := (^Hardened_Allocator_Allocation_Header)(rawptr(header_addr))
	region := header.region
	zone := region.zone

	if region == nil {
		return .Invalid_Pointer
	}

	region_start := uintptr(region.usable_start)
	region_end := region_start + uintptr(region.usable_size)

	if !(region_start <= user_addr && user_addr < region_end) {
		return .Invalid_Pointer
	}
	if header.padding < size_of(Hardened_Allocator_Allocation_Header) {
		return .Invalid_Pointer
	}
	if header.block_size <= 0 || header.requested_size < 0 {
		return .Invalid_Pointer
	}

	block_addr := user_addr - uintptr(header.padding)
	block_end := block_addr + uintptr(header.block_size)
	if !(region_start <= block_addr && block_addr < region_end) || block_end > region_end {
		return .Invalid_Pointer
	}
	if block_addr % uintptr(align_of(Hardened_Allocator_Free_Block)) != 0 {
		return .Invalid_Pointer
	}

	block := (^Hardened_Allocator_Free_Block)(rawptr(block_addr))
	block.size = header.block_size
	block.region = region
	block.next = nil

	block = hardened_allocator_coalesce(s, zone, block)
	hardened_allocator_insert_free_block(s, &header.sig, block)

	return nil
}

hardened_allocator_proc :: proc(
	allocator_data: rawptr,
	mode: Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	Allocator_Error,
) {
	s := (^Hardened_Allocator)(allocator_data)

	switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		return nil, .Mode_Not_Implemented

	case .Free:
		return nil, hardened_allocator_free(s, old_memory, loc)

	case .Free_All:
		return nil, .Mode_Not_Implemented

	case .Resize, .Resize_Non_Zeroed:
		return nil, .Mode_Not_Implemented

	case .Query_Features:
		set := (^Allocator_Mode_Set)(old_memory)
		if set != nil {
			set^ = {.Free, .Resize, .Resize_Non_Zeroed, .Query_Features, .Query_Info}
		}
		return nil, nil

	case .Query_Info:
		info := (^Allocator_Query_Info)(old_memory)
		if info != nil && info.pointer != nil {
			ptr := uintptr(info.pointer)
			header := (^Hardened_Allocator_Allocation_Header)(
				rawptr(ptr - uintptr(size_of(Hardened_Allocator_Allocation_Header))),
			)
			region := header.region
			if region == nil {
				return nil, .Invalid_Pointer
			}

			region_start := uintptr(region.usable_start)
			region_end := region_start + uintptr(region.usable_size)
			if !(region_start <= ptr && ptr < region_end) {
				return nil, .Invalid_Pointer
			}

			info.size = header.requested_size
			info.alignment = header.alignment
			return mem.byte_slice(info, size_of(info^)), nil
		}
		return nil, nil
	}

	return nil, nil
}

hardened_allocator_add_region_for_request :: proc(
	s: ^Hardened_Allocator,
	sig: ^Type_Signature,
	size: int,
	alignment: int,
	loc := #caller_location,
) -> Allocator_Error {
	zone := s.metadata.zones[sig.index]
	sync.mutex_guard(&zone.region_mutex)

	minimum_allocation_size := size + size_of(Hardened_Allocator_Allocation_Header)
	if alignment > 1 {
		minimum_allocation_size += alignment - 1
	}

	minimum_block_size := max(size_of(Hardened_Allocator_Free_Block), minimum_allocation_size)

	region_header_size := int(
		hardened_allocator_align_up(
			uintptr(size_of(Hardened_Allocator_Region)),
			uintptr(align_of(Hardened_Allocator_Free_Block)),
		),
	)

	region_alignment := max(
		align_of(Hardened_Allocator_Region),
		align_of(Hardened_Allocator_Free_Block),
	)

	minimum_region_size := region_header_size + minimum_block_size + region_alignment - 1

	region_allocation_size := max(DEFAULT_REGION_SIZE, minimum_region_size)

	raw_region_memory, memory_err := _request_memory(
		region_allocation_size,
		region_alignment,
		s.fallback_allocator,
	)
	if memory_err != nil {
		return memory_err
	}

	raw_start := uintptr(raw_data(raw_region_memory))

	usable_start := hardened_allocator_align_up(raw_start, uintptr(region_alignment))

	alignment_offset := int(usable_start - raw_start)
	usable_size := len(raw_region_memory) - alignment_offset

	region := (^Hardened_Allocator_Region)(rawptr(usable_start))

	region^ = Hardened_Allocator_Region {
		next         = zone.region_list,
		zone         = zone,
		memory       = raw_region_memory,
		type_index   = sig.index,
		usable_start = rawptr(usable_start),
		usable_size  = usable_size,
	}

	zone.region_list = region

	block_addr := usable_start + uintptr(region_header_size)
	block_size := usable_size - region_header_size

	block := (^Hardened_Allocator_Free_Block)(rawptr(block_addr))
	block.size = block_size
	block.region = region
	block.next = nil

	hardened_allocator_insert_free_block(s, sig, block)

	return nil
}

@(require_results)
hardened_allocator_find_block :: proc(
	s: ^Hardened_Allocator,
	sig: ^Type_Signature,
	size: int,
	alignment: int,
) -> (
	block: ^Hardened_Allocator_Free_Block,
	prev: ^Hardened_Allocator_Free_Block,
	size_index: int,
	used_size: int,
	padding: int,
	lock: ^sync.Mutex,
) {
	minimum_possible := size + size_of(Hardened_Allocator_Allocation_Header)
	if alignment > 1 {
		minimum_possible += alignment - 1
	}

	initial_size_class := hardened_allocator_class_index(s, minimum_possible)

	zone := s.metadata.zones[sig.index]

	for size_class_index in initial_size_class ..< SIZE_CLASS_COUNT {
		lock = &zone.free_lists_mutex[size_class_index]
		sync.lock(lock)

		prev = nil
		block = zone.free_lists[size_class_index]
		for block != nil {
			used_size, padding = hardened_allocator_required_block_size(block, size, alignment)
			if used_size <= block.size {
				size_index = size_class_index
				return
			}
			prev = block
			block = block.next
		}

		sync.unlock(lock)
	}

	return nil, nil, 0, 0, 0, nil
}

@(require_results)
hardened_allocator_required_block_size :: proc(
	block: ^Hardened_Allocator_Free_Block,
	size: int,
	alignment: int,
) -> (
	used_size: int,
	padding: int,
) {
	block_addr := uintptr(block)
	padding = mem.calc_padding_with_header(
		block_addr,
		uintptr(alignment),
		size_of(Hardened_Allocator_Allocation_Header),
	)

	allocation_end := block_addr + uintptr(padding + size)
	aligned_end := hardened_allocator_align_up(
		allocation_end,
		uintptr(align_of(Hardened_Allocator_Free_Block)),
	)
	used_size = int(aligned_end - block_addr)
	return
}

@(require_results)
hardened_allocator_align_up :: proc(value, alignment: uintptr) -> uintptr {
	if alignment <= 1 {
		return value
	}
	rem := value % alignment
	if rem == 0 {
		return value
	}
	return value + (alignment - rem)
}

@(require_results)
hardened_allocator_class_index :: proc(s: ^Hardened_Allocator, size: int) -> int {
	threshold := MIN_SIZE_CLASS
	size_idx := 0

	for size_idx < SIZE_CLASS_COUNT - 1 && size > threshold {
		threshold <<= 1
		size_idx += 1
	}

	return size_idx
}

hardened_allocator_insert_free_block :: proc(
	s: ^Hardened_Allocator,
	sig: ^Type_Signature,
	block: ^Hardened_Allocator_Free_Block,
) {
	size_index := hardened_allocator_class_index(s, block.size)
	zone := s.metadata.zones[sig.index]
	sync.mutex_guard(&zone.free_lists_mutex[size_index])
	block.next = zone.free_lists[size_index]
	zone.free_lists[size_index] = block
}

// The caller should handle locking the free list
hardened_allocator_remove_free_block :: proc(
	s: ^Hardened_Allocator,
	zone: ^Hardened_Allocator_Zone,
	index: int,
	prev: ^Hardened_Allocator_Free_Block,
	block: ^Hardened_Allocator_Free_Block,
) {
	if prev == nil {
		zone.free_lists[index] = block.next
	} else {
		prev.next = block.next
	}
	block.next = nil
}

@(require_results)
hardened_allocator_coalesce :: proc(
	s: ^Hardened_Allocator,
	zone: ^Hardened_Allocator_Zone,
	block: ^Hardened_Allocator_Free_Block,
) -> ^Hardened_Allocator_Free_Block {
	for size_index in 0 ..< SIZE_CLASS_COUNT {
		sync.mutex_guard(&zone.free_lists_mutex[size_index])

		prev: ^Hardened_Allocator_Free_Block = nil
		other := zone.free_lists[size_index]

		for other != nil {
			if other.region != block.region {
				prev = other
				other = other.next
				continue
			}

			block_start := uintptr(block)
			block_end := block_start + uintptr(block.size)
			other_start := uintptr(other)
			other_end := other_start + uintptr(other.size)

			if other_end == block_start {
				hardened_allocator_remove_free_block(s, zone, size_index, prev, other)
				other.size += block.size
				return other
			}

			if block_end == other_start {
				hardened_allocator_remove_free_block(s, zone, size_index, prev, other)
				block.size += other.size
				return block
			}

			prev = other
			other = other.next
		}
	}

	return block
}
