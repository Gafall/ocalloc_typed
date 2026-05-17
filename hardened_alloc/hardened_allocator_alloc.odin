package hardened_alloc

import "core:mem"
import "core:slice"
import "core:sync"

@(require_results)
hardened_allocator_alloc_slice :: proc($T: typeid, count: int) -> ([]T, Allocator_Error) {
	raw, err := _request_memory(count * size_of(T))
	if err != nil || raw == nil {
		return nil, err
	}

	temp := slice.from_ptr(cast(^T)raw_data(raw), count)
	mem.zero_slice(temp)

	return temp, nil
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

	block: ^Hardened_Allocator_Free_Block
	prev: ^Hardened_Allocator_Free_Block
	size_index: int
	used_size: int
	padding: int
	lock: ^sync.Mutex

	for {
		block, prev, size_index, used_size, padding, lock = hardened_allocator_find_block(
			s,
			sig,
			size,
			alignment,
		)

		if block != nil {
			if !hardened_allocator_validate_free_block(block, s.metadata.secrets) {
				panic("Free list block was invalid")
			}
			zone := s.metadata.zones[sig.index]
			hardened_allocator_check_zone(zone, s.metadata.secrets)
			hardened_allocator_remove_free_block(s, zone, size_index, prev, block)
			sync.unlock(lock)
			break
		}

		err := hardened_allocator_alloc_region(s, sig, size, alignment, loc)
		if err != nil {
			return nil, err
		}
	}

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
		hardened_allocator_tag_free_block(tail, s.metadata.secrets)

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

	hardened_allocator_tag_allocation_header(header, s.metadata.secrets)

	return mem.byte_slice(rawptr(user_addr), size), nil
}

@(require_results)
hardened_allocator_alloc_zone :: proc(
	s: ^Hardened_Allocator,
	zone: ^^Hardened_Allocator_Zone,
	zone_index: int,
) -> Allocator_Error {
	raw, err := _request_memory(size_of(Hardened_Allocator_Zone))
	if err != nil {
		return err
	}
	zone^ = cast(^Hardened_Allocator_Zone)raw_data(raw)

	zone^.region_list = nil
	zone^.region_mutex = {}

	ferr: Allocator_Error
	zone^.free_lists, ferr = hardened_allocator_alloc_slice(
		^Hardened_Allocator_Free_Block,
		s.metadata.size_class_count,
	)
	if ferr != nil {
		return ferr
	}

	mferr: Allocator_Error
	zone^.free_lists_mutex, mferr = hardened_allocator_alloc_slice(
		sync.Mutex,
		s.metadata.size_class_count,
	)
	if mferr != nil {
		return mferr
	}

	qerr: Allocator_Error
	zone^.quarantine, qerr = hardened_allocator_alloc_slice(
		^Hardened_Allocator_Free_Block,
		s.metadata.quarantine_size,
	)

	hardened_allocator_tag_zone(zone^, s.metadata.secrets)

	return nil
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
	if !s.initialized || s.metadata == nil {
		panic("Allocator was never initialized")
	}
	if !hardened_allocator_validate_metadata(s.metadata, s.metadata.secrets) {
		panic("Allocator state was invalid")
	}

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

hardened_allocator_alloc_region :: proc(
	s: ^Hardened_Allocator,
	sig: ^Type_Signature,
	size: int,
	alignment: int,
	loc := #caller_location,
) -> Allocator_Error {
	zone := s.metadata.zones[sig.index]
	hardened_allocator_check_zone(zone, s.metadata.secrets)
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

	raw_region_memory, memory_err := _request_memory(region_allocation_size)
	if memory_err != nil {
		return memory_err
	}

	raw_start := uintptr(raw_data(raw_region_memory))

	usable_start := hardened_allocator_align_up(raw_start, uintptr(region_alignment))

	alignment_offset := int(usable_start - raw_start)
	usable_size := len(raw_region_memory) - alignment_offset

	region := (^Hardened_Allocator_Region)(rawptr(usable_start))

	if zone.region_list != nil {
		if !hardened_allocator_validate_region(zone.region_list, s.metadata.secrets) {
			panic("A memory region has been invalid")
		}
	}

	region^ = Hardened_Allocator_Region {
		next         = zone.region_list,
		zone         = zone,
		memory       = raw_region_memory,
		type_index   = sig.index,
		usable_start = rawptr(usable_start),
		usable_size  = usable_size,
	}

	hardened_allocator_tag_region(region, s.metadata.secrets)

	sync.lock(&zone.tag_mutex)
	zone.region_list = region
	hardened_allocator_tag_zone(zone, s.metadata.secrets)
	sync.unlock(&zone.tag_mutex)

	block_addr := usable_start + uintptr(region_header_size)
	block_size := usable_size - region_header_size

	block := (^Hardened_Allocator_Free_Block)(rawptr(block_addr))
	block.size = block_size
	block.region = region
	block.next = nil
	hardened_allocator_tag_free_block(block, s.metadata.secrets)

	hardened_allocator_insert_free_block(s, sig, block)

	return nil
}
