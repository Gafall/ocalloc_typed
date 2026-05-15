package hardened_alloc

import "base:runtime"
import "core:mem"
import "core:reflect"
import "core:slice"
import "core:sync"

// The following code is largely based on how some of the official Odin allocators
// https://github.com/odin-lang/Odin/blob/16ebdc19dd1743d8432aefa55cbc847530399d4d/core/mem/allocators.odin

new_typed :: proc(
	$T: typeid,
	allocator := context.allocator,
	loc := #caller_location,
) -> (
	^T,
	Allocator_Error,
) {
	if allocator.procedure == hardened_allocator_proc {
		return hardened_allocator_alloc(allocator.data, T)
	}
	return new(T, allocator, loc)
}

Type_Signature :: struct {
	hash:     u64,
	features: bit_set[Signature_Feature],
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
	Has_Pointer,
	Has_Procedure,
	Has_Buffer,
	Has_Opaque,
}

Type_Class_Policy :: enum {
	Manual_Registry,
	Type_Signature,
}

Type_Class :: enum {
	Data, // for plain types
	Buffer, // for buffers
	Pointer_Containing, // for things that have pointers
	Procedure_Containing, // for things that have procedures
	Opaque, // fallback for types that are hard to classify
}

Hardened_Allocator :: struct {
	fallback_allocator: Allocator, // used for allocating regions on some OS
	regions:            ^Hardened_Allocator_Region,
	region_mutex:       sync.Mutex,
	free_lists:         []^Hardened_Allocator_Free_Block,
	free_lists_mutex:   []sync.Mutex,
	type_class_policy:  Type_Class_Policy,
}

Hardened_Allocator_Region :: struct {
	next:         ^Hardened_Allocator_Region,
	memory:       []byte,
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
	region:         ^Hardened_Allocator_Region,
}

@(require_results)
hardened_allocator :: proc(s: ^Hardened_Allocator) -> Allocator {
	return Allocator{procedure = hardened_allocator_proc, data = s}
}

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

hardened_allocator_determine_type_signature :: proc($T: typeid) -> Type_Signature {
	sig := Type_Signature{}

	hardened_allocator_generate_signature(T, &sig, 0)

	return sig
}

hardened_allocator_generate_signature :: proc($T: typeid, sig: ^Type_Signature, depth: int) {
	if depth >= MAX_RECURSION_DEPTH {
		sig.truncated = true
		sig.features += {.Has_Opaque}
		hash_add_token(&sig.hash, .Opaque)
		hash_add_token(&sig.hash, .Truncated)
		return
	}

	info := type_info_of(T)
	base := reflect.type_info_base(T)

	if reflect.is_procedure(base) {
		sig.features += {.Has_Procedure}
		hash_add_token(&sig.hash, .Procedure)
		return
	}

	if reflect.is_pointer(base) || reflect.is_multi_pointer(base) || reflect.is_soa_pointer(base) {
		sig.features += {.Has_Pointer}
		hash_add_token(&sig.hash, .Pointer)
		return
	}

	if reflect.is_string(base) {
		sig.features += {.Has_Buffer}
		hash_add_token(&sig.hash, .Buffer)
		return
	}

	if reflect.is_slice(base) || reflect.is_dynamic_array(base) {
		sig.features += {.Has_Pointer}
		sig.features += {.Has_Buffer}
		hash_add_token(&sig.hash, .Pointer)
		hash_add_token(&sig.hash, .Buffer)
		return
	}
	if reflect.is_any(base) || reflect.is_dynamic_map(base) {
		sig.features += {.Has_Pointer}
		sig.features += {.Has_Opaque}
		hash_add_token(&sig.hash, .Pointer)
		hash_add_token(&sig.hash, .Opaque)
		return
	}

	if reflect.is_union(base) || reflect.is_raw_union(base) {
		sig.features += {.Has_Opaque}
		hash_add_token(&sig.hash, .Opaque)
		return
	}

	if reflect.is_array(base) ||
	   reflect.is_enumerated_array(base) ||
	   reflect.is_fixed_capacity_dynamic_array(base) {
		hash_add_token(&sig.hash, .Array_Begin)
		elem_type := reflect.typeid_elem(T)
		elem_info := type_info_of(elem_type)
		elem_base := reflect.type_info_base(elem_info)

		switch var in elem_base {
		case runtime.Type_Info_Array:
			hash_add_int(&sig.hash, var.count)
		case runtime.Type_Info_Enumerated_Array:
			hash_add_int(&sig.hash, var.count)
		case runtime.Type_Info_Fixed_Capacity_Dynamic_Array:
			hash_add_int(&sig.hash, var.capacity)
		}

		if reflect.is_byte(elem_base) {
			hash_add_token(&sig.hash, .Buffer)
			sig.features += {.Has_Buffer}
		} else {
			hardened_allocator_generate_signature(elem_type, sig, depth + 1)
		}

		hash_add_token(&sig.hash, .Array_End)
		return
	}

	if reflect.is_struct(base) {
		hash_add_token(&sig.hash, .Struct_Begin)
		field_types := reflect.struct_field_types(T)

		for field_info in field_types {
			hardened_allocator_generate_signature(field_info.id, sig, depth + 1)
		}

		hash_add_token(&sig.hash, .Struct_End)
		return
	}

	hash_add_token(&sig.hash, .Data)
	return
}

hardened_allocator_init :: proc(
	s: ^Hardened_Allocator,
	fallback_allocator := context.allocator,
	type_policy := Type_Class_Policy.Type_Signature,
	loc := #caller_location,
) {
	s.fallback_allocator = fallback_allocator
	s.regions = nil
	s.region_mutex = {}
	s.type_class_policy = type_policy

	ferr: Allocator_Error
	s.free_lists, ferr = hardened_allocator_alloc_slice(
		^Hardened_Allocator_Free_Block,
		SIZE_CLASS_COUNT,
		fallback_allocator,
	)
	if ferr != nil {
		panic("Failed to initilize allocator")
	}

	mferr: Allocator_Error
	s.free_lists_mutex, mferr = hardened_allocator_alloc_slice(
		sync.Mutex,
		SIZE_CLASS_COUNT,
		fallback_allocator,
	)
	if mferr != nil {
		panic("Failed to initilize allocator")
	}
}

@(require_results)
hardened_allocator_alloc :: proc(
	s: ^Hardened_Allocator,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {
	bytes, err := hardened_allocator_alloc_bytes(s, size, alignment, loc)
	return raw_data(bytes), err
}

@(require_results)
hardened_allocator_alloc_bytes :: proc(
	s: ^Hardened_Allocator,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	[]byte,
	Allocator_Error,
) {
	bytes, err := hardened_allocator_alloc_bytes_non_zeroed(s, size, alignment, loc)
	if bytes != nil {
		mem.zero_slice(bytes)
	}
	return bytes, err
}

@(require_results)
hardened_allocator_alloc_non_zeroed :: proc(
	s: ^Hardened_Allocator,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {
	bytes, err := hardened_allocator_alloc_bytes_non_zeroed(s, size, alignment, loc)
	return raw_data(bytes), err
}

hardened_allocator_destroy :: proc(s: ^Hardened_Allocator, loc := #caller_location) {
	region := s.regions
	for region != nil {
		next := region.next

		_free_memory(region.memory, s.fallback_allocator)
		region = next
	}

	s.regions = nil
	s.region_mutex = {}
	hardened_allocator_free_slice(
		^Hardened_Allocator_Free_Block,
		s.free_lists,
		s.fallback_allocator,
	)
	hardened_allocator_free_slice(sync.Mutex, s.free_lists_mutex, s.fallback_allocator)
	s.fallback_allocator = {}
}

@(require_results, no_sanitize_address)
hardened_allocator_alloc_bytes_non_zeroed :: proc(
	s: ^Hardened_Allocator,
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

	block, prev, class_index, used_size, padding, lock := hardened_allocator_find_block(
		s,
		size,
		alignment,
	)
	if block == nil {
		err := hardened_allocator_add_region_for_request(s, size, alignment, loc)
		if err != nil {
			return nil, err
		}

		block, prev, class_index, used_size, padding, lock = hardened_allocator_find_block(
			s,
			size,
			alignment,
		)
		if block == nil {
			return nil, .Out_Of_Memory
		}
	}

	hardened_allocator_remove_free_block(s, class_index, prev, block)
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

		hardened_allocator_insert_free_block(s, tail)
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

	block = hardened_allocator_coalesce(s, block)
	hardened_allocator_insert_free_block(s, block)

	return nil
}

@(require_results)
hardened_allocator_resize :: proc(
	s: ^Hardened_Allocator,
	old_memory: rawptr,
	old_size: int,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {
	bytes, err := hardened_allocator_resize_bytes(
		s,
		mem.byte_slice(old_memory, old_size),
		size,
		alignment,
	)
	return raw_data(bytes), err
}

@(require_results)
hardened_allocator_resize_bytes :: proc(
	s: ^Hardened_Allocator,
	old_data: []byte,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	[]byte,
	Allocator_Error,
) {
	return mem.default_resize_bytes_align(old_data, size, alignment, hardened_allocator(s))
}

@(require_results)
hardened_allocator_resize_non_zeroed :: proc(
	s: ^Hardened_Allocator,
	old_memory: rawptr,
	old_size: int,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {
	bytes, err := hardened_allocator_resize_bytes_non_zeroed(
		s,
		mem.byte_slice(old_memory, old_size),
		size,
		alignment,
	)
	return raw_data(bytes), err
}

@(require_results)
hardened_allocator_resize_bytes_non_zeroed :: proc(
	s: ^Hardened_Allocator,
	old_data: []byte,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	[]byte,
	Allocator_Error,
) {
	return mem.default_resize_bytes_align_non_zeroed(
		old_data,
		size,
		alignment,
		hardened_allocator(s),
	)
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
	case .Alloc:
		return hardened_allocator_alloc_bytes(s, size, alignment, loc)

	case .Alloc_Non_Zeroed:
		return hardened_allocator_alloc_bytes_non_zeroed(s, size, alignment, loc)

	case .Free:
		return nil, hardened_allocator_free(s, old_memory, loc)

	case .Free_All:
		return nil, .Mode_Not_Implemented

	case .Resize:
		return hardened_allocator_resize_bytes(
			s,
			mem.byte_slice(old_memory, old_size),
			size,
			alignment,
		)

	case .Resize_Non_Zeroed:
		return hardened_allocator_resize_bytes_non_zeroed(
			s,
			mem.byte_slice(old_memory, old_size),
			size,
			alignment,
		)

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
	size: int,
	alignment: int,
	loc := #caller_location,
) -> Allocator_Error {
	sync.mutex_guard(&s.region_mutex)

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
		next         = s.regions,
		memory       = raw_region_memory,
		usable_start = rawptr(usable_start),
		usable_size  = usable_size,
	}

	s.regions = region

	block_addr := usable_start + uintptr(region_header_size)
	block_size := usable_size - region_header_size

	block := (^Hardened_Allocator_Free_Block)(rawptr(block_addr))
	block.size = block_size
	block.region = region
	block.next = nil

	hardened_allocator_insert_free_block(s, block)

	return nil
}

@(require_results)
hardened_allocator_find_block :: proc(
	s: ^Hardened_Allocator,
	size: int,
	alignment: int,
) -> (
	block: ^Hardened_Allocator_Free_Block,
	prev: ^Hardened_Allocator_Free_Block,
	class_index: int,
	used_size: int,
	padding: int,
	lock: ^sync.Mutex,
) {
	minimum_possible := size + size_of(Hardened_Allocator_Allocation_Header)
	if alignment > 1 {
		minimum_possible += alignment - 1
	}

	start_class := hardened_allocator_class_index(minimum_possible)

	for class in start_class ..< SIZE_CLASS_COUNT {
		lock = &s.free_lists_mutex[class]
		sync.lock(lock)

		prev = nil
		block = s.free_lists[class]
		for block != nil {
			used_size, padding = hardened_allocator_required_block_size(block, size, alignment)
			if used_size <= block.size {
				class_index = class
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
hardened_allocator_class_index :: proc(size: int) -> int {
	threshold := MIN_SIZE_CLASS
	index := 0

	for index < SIZE_CLASS_COUNT - 1 && size > threshold {
		threshold <<= 1
		index += 1
	}

	return index
}

hardened_allocator_insert_free_block :: proc(
	s: ^Hardened_Allocator,
	block: ^Hardened_Allocator_Free_Block,
) {
	class_index := hardened_allocator_class_index(block.size)
	sync.mutex_guard(&s.free_lists_mutex[class_index])
	block.next = s.free_lists[class_index]
	s.free_lists[class_index] = block
}

// the caller should handle locking the free list
hardened_allocator_remove_free_block :: proc(
	s: ^Hardened_Allocator,
	class_index: int,
	prev: ^Hardened_Allocator_Free_Block,
	block: ^Hardened_Allocator_Free_Block,
) {
	if prev == nil {
		s.free_lists[class_index] = block.next
	} else {
		prev.next = block.next
	}
	block.next = nil
}

@(require_results)
hardened_allocator_coalesce :: proc(
	s: ^Hardened_Allocator,
	block: ^Hardened_Allocator_Free_Block,
) -> ^Hardened_Allocator_Free_Block {
	for class_index in 0 ..< SIZE_CLASS_COUNT {
		sync.mutex_guard(&s.free_lists_mutex[class_index])

		prev: ^Hardened_Allocator_Free_Block = nil
		other := s.free_lists[class_index]

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
				hardened_allocator_remove_free_block(s, class_index, prev, other)
				other.size += block.size
				return other
			}

			if block_end == other_start {
				hardened_allocator_remove_free_block(s, class_index, prev, other)
				block.size += other.size
				return block
			}

			prev = other
			other = other.next
		}
	}

	return block
}
