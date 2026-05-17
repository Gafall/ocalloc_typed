package main

import "../hardened_alloc"
import "core:fmt"


// Demontstrates metadata corruption detection
// the program should panic with Allocated block was invalid
main :: proc() {
	all: hardened_alloc.Hardened_Allocator
	err := hardened_alloc.hardened_allocator_init(&all)
	if err != nil {
		fmt.println(err)
		return
	}
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	arr, aerr := hardened_alloc.typed_new([64]u8)
	if aerr != nil {
		fmt.println(aerr)
		return
	}

	user_addr := uintptr(rawptr(arr))
	header_addr :=
		user_addr - uintptr(size_of(hardened_alloc.Hardened_Allocator_Allocation_Header))
	header := (^hardened_alloc.Hardened_Allocator_Allocation_Header)(rawptr(header_addr))

	fmt.println("Corrupting allocation header.requested_size")
	header.requested_size += 1

	fmt.println("Freeing corrupted allocation and it should panic")
	free(arr)

	// Shouldn't happen
	fmt.println("Metadata corruption was not detected")
}
