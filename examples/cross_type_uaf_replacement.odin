package main

import "../hardened_alloc"
import "core:fmt"

// Demontstrates metadata cross-type UAF replacement
// the program should show the baseline allocator reusing the same address while the hardened allocator does not

Victim :: struct {
	callback: proc(),
	padding:  [56]u8,
}

Attacker_Buffer :: struct {
	bytes: [64]u8,
}

baseline_demo :: proc() {
	fmt.println("Baseline allocator")

	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	victim, verr := hardened_alloc.typed_new(Victim, alignment = align_of(Victim))
	if verr != nil {
		fmt.println(verr)
		return
	}

	victim_addr := uintptr(rawptr(victim))
	free(victim)

	replacement, rerr := hardened_alloc.typed_new(Attacker_Buffer, alignment = align_of(Victim))
	if rerr != nil {
		fmt.println(rerr)
		return
	}

	replacement_addr := uintptr(rawptr(replacement))

	fmt.printf("Victim address:      0x%x\n", victim_addr)
	fmt.printf("Replacement address: 0x%x\n", replacement_addr)
	fmt.printf("Reused address: %v\n\n", victim_addr == replacement_addr)

	free(replacement)
}

hardened_demo :: proc() {
	fmt.println("Hardened allocator using manual type registry to garuntee different zones")

	manual_registry: hardened_alloc.Manual_Type_Registry = {
		type_entries       = {
			hardened_alloc.manual_entry(Victim, .Procedure_Containing),
			hardened_alloc.manual_entry(Attacker_Buffer, .Buffer),
		},
		fallback_class     = .Opaque,
		use_fallback_class = false,
	}

	all: hardened_alloc.Hardened_Allocator
	err := hardened_alloc.hardened_allocator_init(
		&all,
		type_policy = hardened_alloc.Type_Class_Policy.Manual_Registry,
		manual_type_registry = manual_registry,
		quarantine_size = 1,
	)
	if err != nil {
		fmt.println(err)
		return
	}
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	victim1, aerr := hardened_alloc.typed_new(Victim, alignment = align_of(Victim))
	if aerr != nil {
		fmt.println(aerr)
		return
	}
	victim2, berr := hardened_alloc.typed_new(Victim, alignment = align_of(Victim))
	if berr != nil {
		fmt.println(berr)
		return
	}

	victim1_addr := uintptr(rawptr(victim1))
	victim2_addr := uintptr(rawptr(victim2))

	free(victim1)
	free(victim2)

	replacement, rerr := hardened_alloc.typed_new(Attacker_Buffer, alignment = align_of(Victim))
	if berr != nil {
		fmt.println(rerr)
		return
	}

	replacement_addr := uintptr(rawptr(replacement))

	fmt.printf("Victim 1 address:    0x%x\n", victim1_addr)
	fmt.printf("Victim 2 address:    0x%x\n", victim2_addr)
	fmt.printf("Buffer address:      0x%x\n", replacement_addr)
	fmt.printf("Reused victim 1:      %v\n", replacement_addr == victim1_addr)
	fmt.printf("Reused victim 2:      %v\n", replacement_addr == victim2_addr)
	fmt.println("both should be false")

	free(replacement)
}

main :: proc() {
	baseline_demo()
	hardened_demo()
}
