package hardened_alloc

import "base:runtime"
import "core:mem"
import "core:sync"

// The following code is largely based on how some of the official Odin allocators
// https://github.com/odin-lang/Odin/blob/16ebdc19dd1743d8432aefa55cbc847530399d4d/core/mem/allocators.odin

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
	free_lists:       []^Hardened_Allocator_Free_Block,
	free_lists_mutex: []sync.Mutex,
	quarantine:       []^Hardened_Allocator_Free_Block,
	quarantine_count: int,
	tag:              [16]u8,
	region_mutex:     sync.Mutex,
	quarantine_mutex: sync.Mutex,
	tag_mutex:        sync.Mutex,
}

Hardened_Allocator :: struct {
	metadata:    ^Hardened_Allocator_Metadata,
	initialized: bool,
}

Hardened_Allocator_Metadata :: struct {
	secrets:              ^Hardened_Allocator_Secrets,
	zones:                []^Hardened_Allocator_Zone,
	type_class_policy:    Type_Class_Policy,
	manual_type_registry: Manual_Type_Registry,
	type_bucket_count:    int,
	size_class_count:     int,
	quarantine_size:      int,
	tag:                  [16]u8,
}

Hardened_Allocator_Region :: struct {
	next:         ^Hardened_Allocator_Region,
	zone:         ^Hardened_Allocator_Zone,
	memory:       []byte,
	type_index:   int,
	usable_start: rawptr,
	usable_size:  int,
	tag:          [16]u8,
}

Hardened_Allocator_Free_Block :: struct #align (align_of(uintptr)) {
	size:   int,
	region: ^Hardened_Allocator_Region,
	next:   ^Hardened_Allocator_Free_Block,
	tag:    [16]u8,
}

Hardened_Allocator_Allocation_Header :: struct #align (align_of(uintptr)) {
	block_size:     int,
	requested_size: int,
	alignment:      int,
	padding:        int,
	sig:            Type_Signature,
	region:         ^Hardened_Allocator_Region,
	tag:            [16]u8,
}

Hardened_Allocator_Secrets :: struct {
	zone_key:              [32]u8,
	region_key:            [32]u8,
	metadata_key:          [32]u8,
	allocation_header_key: [32]u8,
	free_block_key:        [32]u8,
	type_class_seed:       u64,
	validate_allocator:    bool,
}

@(require_results)
hardened_allocator :: proc(s: ^Hardened_Allocator) -> Allocator {
	return Allocator{procedure = hardened_allocator_proc, data = s}
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
			set^ = {.Free, .Query_Features, .Query_Info}
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

	hardened_allocator_check_zone(zone, s.metadata.secrets)

	for size_class_index in initial_size_class ..< s.metadata.size_class_count {
		lock = &zone.free_lists_mutex[size_class_index]
		sync.lock(lock)

		prev = nil
		block = zone.free_lists[size_class_index]
		for block != nil {
			if !hardened_allocator_validate_free_block(block, s.metadata.secrets) {
				panic("Free list block was invalid while traversing free list")
			}
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

	for size_idx < s.metadata.size_class_count - 1 && size > threshold {
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
	if !hardened_allocator_validate_free_block(block, s.metadata.secrets) {
		panic("Free list block was invalid")
	}
	size_index := hardened_allocator_class_index(s, block.size)
	zone := s.metadata.zones[sig.index]
	hardened_allocator_check_zone(zone, s.metadata.secrets)
	sync.mutex_guard(&zone.free_lists_mutex[size_index])
	sync.mutex_guard(&zone.tag_mutex)
	block.next = zone.free_lists[size_index]

	hardened_allocator_tag_free_block(block, s.metadata.secrets)
	zone.free_lists[size_index] = block
	hardened_allocator_tag_zone(zone, s.metadata.secrets)
}

// IMPORTNAT: The caller should handle locking the free list
hardened_allocator_remove_free_block :: proc(
	s: ^Hardened_Allocator,
	zone: ^Hardened_Allocator_Zone,
	index: int,
	prev: ^Hardened_Allocator_Free_Block,
	block: ^Hardened_Allocator_Free_Block,
) {
	if !hardened_allocator_validate_free_block(block, s.metadata.secrets) {
		panic("Free list block was invalid")
	}
	hardened_allocator_check_zone(zone, s.metadata.secrets)
	if prev == nil {
		sync.mutex_guard(&zone.tag_mutex)
		zone.free_lists[index] = block.next
		hardened_allocator_tag_zone(zone, s.metadata.secrets)
	} else {
		if !hardened_allocator_validate_free_block(prev, s.metadata.secrets) {
			panic("Free list block was invalid")
		}
		prev.next = block.next
		hardened_allocator_tag_free_block(prev, s.metadata.secrets)
	}
	block.next = nil
	hardened_allocator_tag_free_block(block, s.metadata.secrets)
}
