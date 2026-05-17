package main

import "../hardened_alloc"
import "core:fmt"


// Demontstrates metadata corruption detection
// the program should panic with Free list block was invalid while traversing free list
main :: proc() {
	all: hardened_alloc.Hardened_Allocator
	err := hardened_alloc.hardened_allocator_init(&all)
	if err != nil {
		fmt.println(err)
		return
	}
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	obj, oerr := hardened_alloc.typed_new([64]u8)
	if oerr != nil {
		fmt.println(oerr)
		return
	}

	sig := hardened_alloc.hardened_allocator_determine_type_signature(&all, [64]u8)
	zone := all.metadata.zones[sig.index]

	fake: hardened_alloc.Hardened_Allocator_Free_Block
	fake.size = 4096
	fake.region = nil
	fake.next = nil

	fmt.println("Inserting forged free list blcok")
	for i in 0 ..< len(zone.free_lists) {
		zone.free_lists[i] = &fake
	}

	fmt.println("Allocating again and should panic")
	_, nerr := hardened_alloc.typed_new([64]u8)
	if nerr != nil {
		fmt.println(nerr)
		return
	}

	// Shouldn't happen
	fmt.println("ERROR: fake chunk insertion was not detected")
}
