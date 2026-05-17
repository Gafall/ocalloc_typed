package hardened_alloc

import "core:crypto"
import "core:math/rand"
import "core:slice"
import "core:sync"

hardened_allocator_free_slice :: proc($T: typeid, s: []T) -> Allocator_Error {
	if s == nil {
		return nil
	}

	raw := slice.from_ptr(cast(^u8)raw_data(s), len(s) * size_of(T))

	return _free_memory(raw)
}

hardened_allocator_destroy :: proc(s: ^Hardened_Allocator, loc := #caller_location) {
	for &zone in s.metadata.zones {
		region := zone.region_list
		for region != nil {
			next := region.next

			_free_memory(region.memory)
			region = next
		}

		zone.region_list = nil
		zone.region_mutex = {}
		hardened_allocator_free_slice(^Hardened_Allocator_Free_Block, zone.free_lists)
		hardened_allocator_free_slice(sync.Mutex, zone.free_lists_mutex)
		hardened_allocator_free_slice(^Hardened_Allocator_Free_Block, zone.quarantine)

		_free_memory(slice.bytes_from_ptr(zone, size_of(Hardened_Allocator_Zone)))
	}

	hardened_allocator_free_slice(^Hardened_Allocator_Zone, s.metadata.zones)
	hardened_allocator_free_slice(Manual_Type_Entry, s.metadata.manual_type_registry.type_entries)

	_free_memory(slice.bytes_from_ptr(s.metadata, size_of(Hardened_Allocator_Metadata)))
}

hardened_allocator_quarantine :: proc(
	s: ^Hardened_Allocator,
	zone: ^Hardened_Allocator_Zone,
	block: ^Hardened_Allocator_Free_Block,
) -> ^Hardened_Allocator_Free_Block {
	hardened_allocator_check_zone(zone, s.metadata.secrets)
	sync.mutex_guard(&zone.quarantine_mutex)
	if !hardened_allocator_validate_free_block(block, s.metadata.secrets) {
		panic("Free list block was invalid")
	}

	if zone.quarantine_count + 1 <= s.metadata.quarantine_size {
		sync.mutex_guard(&zone.tag_mutex)
		zone.quarantine[zone.quarantine_count] = block
		zone.quarantine_count += 1
		hardened_allocator_tag_zone(zone, s.metadata.secrets)
		return nil
	}

	gen := crypto.random_generator()
	index := rand.int_max(s.metadata.quarantine_size, gen)
	other := zone.quarantine[index]
	zone.quarantine[index] = block

	if !hardened_allocator_validate_free_block(other, s.metadata.secrets) {
		panic("Free list block was invalid in quarantine")
	}
	return other
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

	if !s.initialized || s.metadata == nil {
		panic("Allocator was never initialized")
	}

	if !hardened_allocator_validate_metadata(s.metadata, s.metadata.secrets) {
		panic("Allocator state was invalid")
	}

	user_addr := uintptr(ptr)
	header_addr := user_addr - uintptr(size_of(Hardened_Allocator_Allocation_Header))
	header := (^Hardened_Allocator_Allocation_Header)(rawptr(header_addr))
	if !hardened_allocator_validate_allocation_header(header, s.metadata.secrets) {
		panic("Allocated block was invalid")
	}

	region := header.region
	if region == nil {
		return .Invalid_Pointer
	}
	zone := region.zone
	if zone == nil {
		return .Invalid_Pointer
	}

	hardened_allocator_check_zone(zone, s.metadata.secrets)

	sig := header.sig
	block_size := header.block_size
	requested_size := header.requested_size
	padding := header.padding


	region_start := uintptr(region.usable_start)
	region_end := region_start + uintptr(region.usable_size)

	if !(region_start <= user_addr && user_addr < region_end) {
		return .Invalid_Pointer
	}
	if padding < size_of(Hardened_Allocator_Allocation_Header) {
		return .Invalid_Pointer
	}
	if block_size <= 0 || requested_size < 0 {
		return .Invalid_Pointer
	}

	block_addr := user_addr - uintptr(padding)
	block_end := block_addr + uintptr(block_size)
	if !(region_start <= block_addr && block_addr < region_end) || block_end > region_end {
		return .Invalid_Pointer
	}
	if block_addr % uintptr(align_of(Hardened_Allocator_Free_Block)) != 0 {
		return .Invalid_Pointer
	}

	block := (^Hardened_Allocator_Free_Block)(rawptr(block_addr))
	block.size = block_size
	block.region = region
	block.next = nil
	hardened_allocator_tag_free_block(block, s.metadata.secrets)

	block = hardened_allocator_quarantine(s, zone, block)

	if block != nil {
		if !hardened_allocator_validate_free_block(block, s.metadata.secrets) {
			panic("Free block was invalid after quarantine")
		}
		block = hardened_allocator_coalesce(s, zone, block)
		hardened_allocator_tag_free_block(block, s.metadata.secrets)
		hardened_allocator_insert_free_block(s, &sig, block)
	}

	return nil
}

@(require_results)
hardened_allocator_coalesce :: proc(
	s: ^Hardened_Allocator,
	zone: ^Hardened_Allocator_Zone,
	block: ^Hardened_Allocator_Free_Block,
) -> ^Hardened_Allocator_Free_Block {
	if !hardened_allocator_validate_free_block(block, s.metadata.secrets) {
		panic("Free list block was invalid")
	}
	if !hardened_allocator_validate_region(block.region, s.metadata.secrets) {
		panic("A memory region has been corrutped")
	}
	hardened_allocator_check_zone(zone, s.metadata.secrets)
	for size_index in 0 ..< s.metadata.size_class_count {
		sync.mutex_guard(&zone.free_lists_mutex[size_index])

		prev: ^Hardened_Allocator_Free_Block = nil
		other := zone.free_lists[size_index]

		for other != nil {
			if !hardened_allocator_validate_free_block(other, s.metadata.secrets) {
				panic("Free list block was invalid")
			}
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
				hardened_allocator_tag_free_block(other, s.metadata.secrets)
				return other
			}

			if block_end == other_start {
				hardened_allocator_remove_free_block(s, zone, size_index, prev, other)
				block.size += other.size
				hardened_allocator_tag_free_block(block, s.metadata.secrets)
				return block
			}

			prev = other
			other = other.next
		}
	}

	return block
}
