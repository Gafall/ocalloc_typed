#+private
package hardened_alloc

import "core:mem"

@(require_results)
_request_memory :: proc(
	size: int,
	alignment: int,
	allocator: Allocator,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	return mem.alloc_bytes_non_zeroed(size, alignment, allocator)
}

_free_memory :: proc(bytes: []byte, allocator: Allocator) -> Allocator_Error {
	return mem.free_bytes(bytes, allocator)
}
