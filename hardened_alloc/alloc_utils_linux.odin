#+build linux, darwin, freebsd, openbsd, netbsd
#+private
package hardened_alloc

import "core:mem"
import "core:sync"

_sbrk_mutex: sync.Mutex

when ODIN_OS == .Darwin {
	foreign import libc "system:System"
} else {
	foreign import libc "system:c"
}

@(default_calling_convention = "c")
foreign libc {
	@(link_name = "sbrk")
	_unix_sbrk :: proc(size: int) -> rawptr ---
}

_expand_heap :: proc "contextless" (size: int) -> rawptr {
	if size <= 0 {
		return nil
	}

	return _unix_sbrk(size)
}

_skrink_heap :: proc "contextless" (size: int) -> rawptr {
	if size >= 0 {
		return nil
	}

	return _unix_sbrk(size)
}

_heap_end :: proc "contextless" () -> rawptr {
	return _unix_sbrk(0)
}

_free_memory :: proc(bytes: []byte, allocator: Allocator) -> Allocator_Error {
	return nil
}

@(require_results)
_request_memory :: proc "contextless" (
	size: int,
	alignment: int,
	allocator: Allocator,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	sync.mutex_lock(&_sbrk_mutex)
	defer sync.mutex_unlock(&_sbrk_mutex)

	head := _expand_heap(size)
	if uintptr(head) == ~uintptr(0) {
		return nil, .Out_Of_Memory
	}

	return mem.byte_slice(head, size), nil
}

