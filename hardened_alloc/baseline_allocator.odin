package hardened_alloc

import "base:runtime"
import "core:log"
import "core:mem"
import "core:sync"

// The following code is largely based on how some of the official Odin allocators
// https://github.com/odin-lang/Odin/blob/16ebdc19dd1743d8432aefa55cbc847530399d4d/core/mem/allocators.odin

Segregated_Free_List :: struct {
	fallback_allocator: Allocator,
	regions:            ^Segregated_Free_List_Region,
	region_mutex:       sync.Mutex,
	free_lists:         [SIZE_CLASS_COUNT]^Segregated_Free_Block,
	free_lists_mutex:   [SIZE_CLASS_COUNT]sync.Mutex,
}

Segregated_Free_List_Region :: struct {
	next:         ^Segregated_Free_List_Region,
	memory:       []byte,
	usable_start: rawptr,
	usable_size:  int,
}

Segregated_Free_Block :: struct #align (align_of(uintptr)) {
	size:   int,
	region: ^Segregated_Free_List_Region,
	next:   ^Segregated_Free_Block,
}

Segregated_Free_List_Allocation_Header :: struct #align (align_of(uintptr)) {
	block_size:     int,
	requested_size: int,
	alignment:      int,
	padding:        int,
	region:         ^Segregated_Free_List_Region,
}

@(require_results)
segregated_free_list_allocator :: proc(s: ^Segregated_Free_List) -> Allocator {
	return Allocator{procedure = segregated_free_list_allocator_proc, data = s}
}

segregated_free_list_init :: proc(
	s: ^Segregated_Free_List,
	fallback_allocator := context.allocator,
	loc := #caller_location,
) {
	s.fallback_allocator = fallback_allocator
	s.regions = nil
	s.free_lists = {}
	s.region_mutex = {}
	s.free_lists_mutex = {}
}

@(require_results)
segregated_free_list_alloc :: proc(
	s: ^Segregated_Free_List,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {
	bytes, err := segregated_free_list_alloc_bytes(s, size, alignment, loc)
	return raw_data(bytes), err
}

@(require_results)
segregated_free_list_alloc_bytes :: proc(
	s: ^Segregated_Free_List,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	[]byte,
	Allocator_Error,
) {
	bytes, err := segregated_free_list_alloc_bytes_non_zeroed(s, size, alignment, loc)
	if bytes != nil {
		mem.zero_slice(bytes)
	}
	return bytes, err
}

@(require_results)
segregated_free_list_alloc_non_zeroed :: proc(
	s: ^Segregated_Free_List,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {
	bytes, err := segregated_free_list_alloc_bytes_non_zeroed(s, size, alignment, loc)
	return raw_data(bytes), err
}

segregated_free_list_destroy :: proc(s: ^Segregated_Free_List, loc := #caller_location) {
	region := s.regions
	for region != nil {
		next := region.next

		_free_memory(region.memory, s.fallback_allocator)
		region = next
	}

	s.regions = nil
	s.free_lists = {}
	s.fallback_allocator = {}
	s.region_mutex = {}
	s.free_lists_mutex = {}
}

@(require_results, no_sanitize_address)
segregated_free_list_alloc_bytes_non_zeroed :: proc(
	s: ^Segregated_Free_List,
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

	block: ^Segregated_Free_Block
	prev: ^Segregated_Free_Block
	class_index: int
	used_size: int
	padding: int
	lock: ^sync.Mutex

	for {
		block, prev, class_index, used_size, padding, lock = segregated_free_list_find_block(
			s,
			size,
			alignment,
		)

		if block != nil {
			segregated_free_list_remove_free_block(s, class_index, prev, block)
			sync.unlock(lock)
			break
		}

		err := segregated_free_list_add_region_for_request(s, size, alignment, loc)
		if err != nil {
			return nil, err
		}
	}

	region := block.region

	remaining := block.size - used_size
	min_split_size := size_of(Segregated_Free_Block) + MIN_SPLIT_PAYLOAD

	if remaining >= min_split_size {
		block_addr := uintptr(block)
		tail_addr := block_addr + uintptr(used_size)

		tail := (^Segregated_Free_Block)(rawptr(tail_addr))
		tail.size = remaining
		tail.region = region
		tail.next = nil

		segregated_free_list_insert_free_block(s, tail)
	} else {
		used_size = block.size
	}

	block_addr := uintptr(block)
	user_addr := block_addr + uintptr(padding)

	header := (^Segregated_Free_List_Allocation_Header)(
		rawptr(user_addr - uintptr(size_of(Segregated_Free_List_Allocation_Header))),
	)

	header.block_size = used_size
	header.requested_size = size
	header.alignment = alignment
	header.padding = padding
	header.region = region

	return mem.byte_slice(rawptr(user_addr), size), nil
}

@(no_sanitize_address)
segregated_free_list_free :: proc(
	s: ^Segregated_Free_List,
	ptr: rawptr,
	loc := #caller_location,
) -> Allocator_Error {
	if ptr == nil {
		return nil
	}

	user_addr := uintptr(ptr)
	header_addr := user_addr - uintptr(size_of(Segregated_Free_List_Allocation_Header))
	header := (^Segregated_Free_List_Allocation_Header)(rawptr(header_addr))
	region := header.region

	if region == nil {
		return .Invalid_Pointer
	}

	region_start := uintptr(region.usable_start)
	region_end := region_start + uintptr(region.usable_size)

	if !(region_start <= user_addr && user_addr < region_end) {
		return .Invalid_Pointer
	}
	if header.padding < size_of(Segregated_Free_List_Allocation_Header) {
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
	if block_addr % uintptr(align_of(Segregated_Free_Block)) != 0 {
		return .Invalid_Pointer
	}

	block := (^Segregated_Free_Block)(rawptr(block_addr))
	block.size = header.block_size
	block.region = region
	block.next = nil

	block = segregated_free_list_coalesce(s, block)
	segregated_free_list_insert_free_block(s, block)
	return nil
}

@(require_results)
segregated_free_list_resize :: proc(
	s: ^Segregated_Free_List,
	old_memory: rawptr,
	old_size: int,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {
	bytes, err := segregated_free_list_resize_bytes(
		s,
		mem.byte_slice(old_memory, old_size),
		size,
		alignment,
	)
	return raw_data(bytes), err
}

@(require_results)
segregated_free_list_resize_bytes :: proc(
	s: ^Segregated_Free_List,
	old_data: []byte,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	[]byte,
	Allocator_Error,
) {
	return mem.default_resize_bytes_align(
		old_data,
		size,
		alignment,
		segregated_free_list_allocator(s),
	)
}

@(require_results)
segregated_free_list_resize_non_zeroed :: proc(
	s: ^Segregated_Free_List,
	old_memory: rawptr,
	old_size: int,
	size: int,
	alignment := DEFAULT_ALIGNMENT,
	loc := #caller_location,
) -> (
	rawptr,
	Allocator_Error,
) {
	bytes, err := segregated_free_list_resize_bytes_non_zeroed(
		s,
		mem.byte_slice(old_memory, old_size),
		size,
		alignment,
	)
	return raw_data(bytes), err
}

@(require_results)
segregated_free_list_resize_bytes_non_zeroed :: proc(
	s: ^Segregated_Free_List,
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
		segregated_free_list_allocator(s),
	)
}

segregated_free_list_allocator_proc :: proc(
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
	s := (^Segregated_Free_List)(allocator_data)

	switch mode {
	case .Alloc:
		return segregated_free_list_alloc_bytes(s, size, alignment, loc)

	case .Alloc_Non_Zeroed:
		return segregated_free_list_alloc_bytes_non_zeroed(s, size, alignment, loc)

	case .Free:
		return nil, segregated_free_list_free(s, old_memory, loc)

	case .Free_All:
		return nil, .Mode_Not_Implemented

	case .Resize:
		return segregated_free_list_resize_bytes(
			s,
			mem.byte_slice(old_memory, old_size),
			size,
			alignment,
		)

	case .Resize_Non_Zeroed:
		return segregated_free_list_resize_bytes_non_zeroed(
			s,
			mem.byte_slice(old_memory, old_size),
			size,
			alignment,
		)

	case .Query_Features:
		set := (^Allocator_Mode_Set)(old_memory)
		if set != nil {
			set^ = {
				.Alloc,
				.Alloc_Non_Zeroed,
				.Free,
				.Resize,
				.Resize_Non_Zeroed,
				.Query_Features,
				.Query_Info,
			}
		}
		return nil, nil

	case .Query_Info:
		info := (^Allocator_Query_Info)(old_memory)
		if info != nil && info.pointer != nil {
			ptr := uintptr(info.pointer)
			header := (^Segregated_Free_List_Allocation_Header)(
				rawptr(ptr - uintptr(size_of(Segregated_Free_List_Allocation_Header))),
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

segregated_free_list_add_region_for_request :: proc(
	s: ^Segregated_Free_List,
	size: int,
	alignment: int,
	loc := #caller_location,
) -> Allocator_Error {
	sync.mutex_guard(&s.region_mutex)

	minimum_allocation_size := size + size_of(Segregated_Free_List_Allocation_Header)
	if alignment > 1 {
		minimum_allocation_size += alignment - 1
	}

	minimum_block_size := max(size_of(Segregated_Free_Block), minimum_allocation_size)

	region_header_size := int(
		segregated_free_list_align_up(
			uintptr(size_of(Segregated_Free_List_Region)),
			uintptr(align_of(Segregated_Free_Block)),
		),
	)

	region_alignment := max(align_of(Segregated_Free_List_Region), align_of(Segregated_Free_Block))

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

	usable_start := segregated_free_list_align_up(raw_start, uintptr(region_alignment))

	alignment_offset := int(usable_start - raw_start)
	usable_size := len(raw_region_memory) - alignment_offset

	region := (^Segregated_Free_List_Region)(rawptr(usable_start))

	region^ = Segregated_Free_List_Region {
		next         = s.regions,
		memory       = raw_region_memory,
		usable_start = rawptr(usable_start),
		usable_size  = usable_size,
	}

	s.regions = region

	block_addr := usable_start + uintptr(region_header_size)
	block_size := usable_size - region_header_size

	block := (^Segregated_Free_Block)(rawptr(block_addr))
	block.size = block_size
	block.region = region
	block.next = nil

	segregated_free_list_insert_free_block(s, block)

	return nil
}

@(require_results)
segregated_free_list_find_block :: proc(
	s: ^Segregated_Free_List,
	size: int,
	alignment: int,
) -> (
	block: ^Segregated_Free_Block,
	prev: ^Segregated_Free_Block,
	class_index: int,
	used_size: int,
	padding: int,
	lock: ^sync.Mutex,
) {
	minimum_possible := size + size_of(Segregated_Free_List_Allocation_Header)
	if alignment > 1 {
		minimum_possible += alignment - 1
	}

	start_class := segregated_free_list_class_index(minimum_possible)

	for class in start_class ..< SIZE_CLASS_COUNT {
		lock = &s.free_lists_mutex[class]
		sync.lock(lock)
		prev = nil
		block = s.free_lists[class]
		
		for block != nil {
			used_size, padding = segregated_free_list_required_block_size(block, size, alignment)
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
segregated_free_list_required_block_size :: proc(
	block: ^Segregated_Free_Block,
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
		size_of(Segregated_Free_List_Allocation_Header),
	)

	allocation_end := block_addr + uintptr(padding + size)
	aligned_end := segregated_free_list_align_up(
		allocation_end,
		uintptr(align_of(Segregated_Free_Block)),
	)
	used_size = int(aligned_end - block_addr)
	return
}

@(require_results)
segregated_free_list_align_up :: proc(value, alignment: uintptr) -> uintptr {
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
segregated_free_list_class_index :: proc(size: int) -> int {
	threshold := MIN_SIZE_CLASS
	index := 0

	for index < SIZE_CLASS_COUNT - 1 && size > threshold {
		threshold <<= 1
		index += 1
	}

	return index
}

segregated_free_list_insert_free_block :: proc(
	s: ^Segregated_Free_List,
	block: ^Segregated_Free_Block,
) {
	class_index := segregated_free_list_class_index(block.size)
	sync.mutex_guard(&s.free_lists_mutex[class_index])
	block.next = s.free_lists[class_index]
	s.free_lists[class_index] = block
}

// the caller should handle locking the free list
segregated_free_list_remove_free_block :: proc(
	s: ^Segregated_Free_List,
	class_index: int,
	prev: ^Segregated_Free_Block,
	block: ^Segregated_Free_Block,
) {
	if prev == nil {
		s.free_lists[class_index] = block.next
	} else {
		prev.next = block.next
	}
	block.next = nil
}

@(require_results)
segregated_free_list_coalesce :: proc(
	s: ^Segregated_Free_List,
	block: ^Segregated_Free_Block,
) -> ^Segregated_Free_Block {
	for class_index in 0 ..< SIZE_CLASS_COUNT {
		sync.mutex_guard(&s.free_lists_mutex[class_index])

		prev: ^Segregated_Free_Block = nil
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
				segregated_free_list_remove_free_block(s, class_index, prev, other)
				other.size += block.size
				return other
			}

			if block_end == other_start {
				segregated_free_list_remove_free_block(s, class_index, prev, other)
				block.size += other.size
				return block
			}

			prev = other
			other = other.next
		}
	}

	return block
}
