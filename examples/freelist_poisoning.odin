package main

import "../hardened_alloc"
import "core:fmt"

// Demontstrates freelist poisining
// the program should panic with a Free list block was invalid while traversing free list
main :: proc() {
	all: hardened_alloc.Hardened_Allocator
	err := hardened_alloc.hardened_allocator_init(&all, quarantine_size = 1)
	if err != nil {
		fmt.println(err)
		return
	}
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	a, aerr := hardened_alloc.typed_new([64]u8)
	if aerr != nil {
		fmt.println(aerr)
		return
	}
	b, berr := hardened_alloc.typed_new([64]u8)
	if berr != nil {
		fmt.println(berr)
		return
	}

	free(a)
	free(b)

	sig := hardened_alloc.hardened_allocator_determine_type_signature(&all, [64]u8)
	zone := all.metadata.zones[sig.index]

	var, victim: ^hardened_alloc.Hardened_Allocator_Free_Block
	for head in zone.free_lists {
		if head != nil {
			victim = head
			break
		}
	}

	fmt.println("Corrupting free block next pointer")
	victim.next = (^hardened_alloc.Hardened_Allocator_Free_Block)(rawptr(uintptr(0xDEADBEEF)))

	fmt.println("Allocating again and should panic")
	_, nerr := hardened_alloc.typed_new([64]u8)
	if nerr != nil {
		fmt.println(nerr)
		return
	}

	// Shouldn't happen
	fmt.println("Freelist poisoning was not detected")
}
