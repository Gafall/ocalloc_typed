package allocator_tests

import "../hardened_alloc"
import "base:runtime"
import "core:log"
import "core:mem"
import "core:testing"
import "core:thread"

// Tests were generated with the help of ChatGPT
// https://chatgpt.com/s/t_6a095861df908191839e3f875287e916

//
// Small deterministic RNG for randomized stress tests.
// Seed it with t.seed so failing runs are reproducible.
//

TEST_BLOCK_SIZE :: 4096

next_u64 :: proc(state: ^u64) -> u64 {
	state^ = state^ * 6364136223846793005 + 1442695040888963407
	return state^
}

rand_range :: proc(state: ^u64, upper: int) -> int {
	return int(next_u64(state) % u64(upper))
}

fill_pattern :: proc(buf: []u8, seed: u8) {
	for i := 0; i < len(buf); i += 1 {
		buf[i] = seed ~ u8(i * 31)
	}
}

check_pattern :: proc(buf: []u8, seed: u8) -> bool {
	for i := 0; i < len(buf); i += 1 {
		if buf[i] != (seed ~ u8(i * 31)) {
			return false
		}
	}
	return true
}

expect_alloc_ok :: proc(t: ^testing.T, buf: []u8, err: mem.Allocator_Error, msg: string) -> bool {
	ok := err == .None && len(buf) > 0
	testing.expect(t, ok, msg)
	return ok
}

//
// 1. Basic allocation/free behavior
//
test_allocator_basic :: proc(t: ^testing.T, allocator: mem.Allocator) {
	arr, err := hardened_alloc.typed_new([128]u8, allocator = allocator)
	if err != .None || arr == nil {
		testing.expect(t, false, "basic allocation failed")
		return
	}
	defer free(rawptr(arr), allocator)

	buf := arr^[:]
	testing.expect_value(t, len(buf), 128)
}

//
// 2. Zero-initialization behavior
//
test_allocator_zeroed_alloc :: proc(t: ^testing.T, allocator: mem.Allocator) {
	arr, err := hardened_alloc.typed_new([256]u8, allocator = allocator)
	if err != .None || arr == nil {
		testing.expect(t, false, "zeroed allocation failed")
		return
	}
	defer free(rawptr(arr), allocator)

	buf := arr^[:]
	testing.expect(t, mem.check_zero(buf), "allocation was expected to return zeroed memory")
}

//
// 3. Alignment coverage
//
test_allocator_alignment :: proc(t: ^testing.T, allocator: mem.Allocator) {
	alignments := [?]int{1, 2, 4, 8, 16, 32, 64, 128}

	for alignment in alignments {
		arr, err := hardened_alloc.typed_new([257]u8, alignment, allocator)
		if err != .None || arr == nil {
			testing.expectf(t, false, "aligned allocation failed for alignment %d", alignment)
			continue
		}

		ptr := rawptr(arr)
		testing.expectf(
			t,
			mem.is_aligned(ptr, alignment),
			"allocation was not aligned to %d bytes",
			alignment,
		)

		free_err := free(rawptr(arr), allocator)
		testing.expect_value(t, free_err, mem.Allocator_Error.None)
	}
}

//
// 4. Pattern-fill correctness
//
test_allocator_pattern_fill :: proc(t: ^testing.T, allocator: mem.Allocator) {
	arr, err := hardened_alloc.typed_new([1024]u8, allocator = allocator)
	if err != .None || arr == nil {
		testing.expect(t, false, "pattern allocation failed")
		return
	}
	defer free(rawptr(arr), allocator)

	buf := arr^[:]
	fill_pattern(buf, 0xA5)
	testing.expect(t, check_pattern(buf, 0xA5), "pattern verification failed")
}

//
// 5. Resize growth must preserve existing bytes
//
test_allocator_resize_grow :: proc(t: ^testing.T, allocator: mem.Allocator) {
	buf, err := mem.alloc_bytes(128, 16, allocator)
	if !expect_alloc_ok(t, buf, err, "resize grow initial allocation failed") {
		return
	}

	fill_pattern(buf, 0x33)

	grown, resize_err := mem.resize_bytes(buf, 512, 16, allocator)
	if resize_err != .None || len(grown) != 512 {
		testing.expect(t, false, "resize grow failed")
		_ = mem.free_bytes(buf, allocator)
		return
	}
	defer mem.free_bytes(grown, allocator)

	testing.expect(
		t,
		check_pattern(grown[:128], 0x33),
		"resize grow did not preserve original data",
	)
}

//
// 6. Resize shrink must preserve prefix bytes
//
test_allocator_resize_shrink :: proc(t: ^testing.T, allocator: mem.Allocator) {
	buf, err := mem.alloc_bytes(512, 16, allocator)
	if !expect_alloc_ok(t, buf, err, "resize shrink initial allocation failed") {
		return
	}

	fill_pattern(buf, 0x6C)

	shrunk, resize_err := mem.resize_bytes(buf, 96, 16, allocator)
	if resize_err != .None || len(shrunk) != 96 {
		testing.expect(t, false, "resize shrink failed")
		_ = mem.free_bytes(buf, allocator)
		return
	}
	defer mem.free_bytes(shrunk, allocator)

	testing.expect(t, check_pattern(shrunk, 0x6C), "resize shrink did not preserve prefix data")
}

//
// 7. Randomized allocate/free/pattern stress test
//
//
// Stress-test allocation types
//

Stress_Kind :: enum {
	Data_Block,
	Pointer_Block,
	Procedure_Block,
	Mixed_Block,
}

STRESS_KIND_COUNT :: 4

Stress_Data_Block :: struct {
	marker: u64,
	data:   [TEST_BLOCK_SIZE]u8,
}

Stress_Pointer_Block :: struct {
	marker: u64,
	next:   ^Stress_Pointer_Block,
	data:   [TEST_BLOCK_SIZE]u8,
}

Stress_Procedure_Block :: struct {
	marker:   u64,
	callback: proc(),
	data:     [TEST_BLOCK_SIZE]u8,
}

Stress_Mixed_Block :: struct {
	marker: u64,
	next:   ^Stress_Mixed_Block,
	count:  int,
	data:   [TEST_BLOCK_SIZE]u8,
}

Stress_Slot :: struct {
	ptr:       rawptr,
	kind:      Stress_Kind,
	seed:      u8,
	live:      bool,
	alignment: int,
}

stress_alloc_typed :: proc(
	kind: Stress_Kind,
	alignment: int,
	allocator: mem.Allocator,
) -> (
	rawptr,
	mem.Allocator_Error,
) {
	switch kind {
	case .Data_Block:
		p, err := hardened_alloc.typed_new(Stress_Data_Block, alignment, allocator)
		return rawptr(p), err

	case .Pointer_Block:
		p, err := hardened_alloc.typed_new(Stress_Pointer_Block, alignment, allocator)
		return rawptr(p), err

	case .Procedure_Block:
		p, err := hardened_alloc.typed_new(Stress_Procedure_Block, alignment, allocator)
		return rawptr(p), err

	case .Mixed_Block:
		p, err := hardened_alloc.typed_new(Stress_Mixed_Block, alignment, allocator)
		return rawptr(p), err
	}

	return nil, .Invalid_Argument
}

stress_init_allocation :: proc(ptr: rawptr, kind: Stress_Kind, seed: u8) {
	switch kind {
	case .Data_Block:
		block := cast(^Stress_Data_Block)ptr
		block.marker = 0xDADA_DADA_DADA_DADA
		fill_pattern(block.data[:], seed)

	case .Pointer_Block:
		block := cast(^Stress_Pointer_Block)ptr
		block.marker = 0xBEEF_BEEF_BEEF_BEEF
		block.next = nil
		fill_pattern(block.data[:], seed)

	case .Procedure_Block:
		block := cast(^Stress_Procedure_Block)ptr
		block.marker = 0xABCD_ABCD_ABCD_ABCD
		block.callback = nil
		fill_pattern(block.data[:], seed)

	case .Mixed_Block:
		block := cast(^Stress_Mixed_Block)ptr
		block.marker = 0xFACE_FACE_FACE_FACE
		block.next = nil
		block.count = 0x1234_5678
		fill_pattern(block.data[:], seed)
	}
}

stress_check_allocation :: proc(ptr: rawptr, kind: Stress_Kind, seed: u8) -> bool {
	switch kind {
	case .Data_Block:
		block := cast(^Stress_Data_Block)ptr
		return block.marker == 0xDADA_DADA_DADA_DADA && check_pattern(block.data[:], seed)

	case .Pointer_Block:
		block := cast(^Stress_Pointer_Block)ptr
		return(
			block.marker == 0xBEEF_BEEF_BEEF_BEEF &&
			block.next == nil &&
			check_pattern(block.data[:], seed) \
		)

	case .Procedure_Block:
		block := cast(^Stress_Procedure_Block)ptr
		return(
			block.marker == 0xABCD_ABCD_ABCD_ABCD &&
			block.callback == nil &&
			check_pattern(block.data[:], seed) \
		)

	case .Mixed_Block:
		block := cast(^Stress_Mixed_Block)ptr
		return(
			block.marker == 0xFACE_FACE_FACE_FACE &&
			block.next == nil &&
			block.count == 0x1234_5678 &&
			check_pattern(block.data[:], seed) \
		)
	}

	return false
}

test_allocator_randomized_stress :: proc(
	t: ^testing.T,
	allocator: mem.Allocator,
	all: ^hardened_alloc.Hardened_Allocator = nil,
) {
	SLOT_COUNT :: 512
	OPS :: 5000000

	slots := [SLOT_COUNT]Stress_Slot{}
	rng := t.seed

	alignments := [?]int{1, 2, 4, 8, 16, 32, 64}

	for op := 0; op < OPS; op += 1 {
		index := rand_range(&rng, SLOT_COUNT)
		slot := &slots[index]

		if !slot.live {
			kind := Stress_Kind(rand_range(&rng, STRESS_KIND_COUNT))
			alignment := alignments[rand_range(&rng, len(alignments))]

			ptr, err := stress_alloc_typed(kind, alignment, allocator)
			if err != .None || ptr == nil {
				if err == .Invalid_Argument && all != nil {
					found := false
					switch kind {
					case .Data_Block:
						_, found = hardened_alloc.hardened_allocator_manual_registry_lookup(
							all,
							Stress_Procedure_Block,
						)
					case .Pointer_Block:
						_, found = hardened_alloc.hardened_allocator_manual_registry_lookup(
							all,
							Stress_Pointer_Block,
						)
					case .Procedure_Block:
						_, found = hardened_alloc.hardened_allocator_manual_registry_lookup(
							all,
							Stress_Procedure_Block,
						)
					case .Mixed_Block:
						_, found = hardened_alloc.hardened_allocator_manual_registry_lookup(
							all,
							Stress_Mixed_Block,
						)
					}

					if !found {
						continue
					}
				}
				testing.expectf(
					t,
					false,
					"stress alloc failed at op %d, kind=%v, alignment=%d",
					op,
					kind,
					alignment,
				)
				continue
			}

			testing.expectf(
				t,
				mem.is_aligned(ptr, alignment),
				"stress allocation alignment failed at op %d, kind=%v, alignment=%d",
				op,
				kind,
				alignment,
			)

			seed := u8(rand_range(&rng, 256))
			stress_init_allocation(ptr, kind, seed)

			slot.ptr = ptr
			slot.kind = kind
			slot.seed = seed
			slot.live = true
			slot.alignment = alignment
		} else {
			testing.expectf(
				t,
				stress_check_allocation(slot.ptr, slot.kind, slot.seed),
				"stress allocation corrupted at op %d, kind=%v",
				op,
				slot.kind,
			)

			free_err := free(slot.ptr, allocator)
			testing.expectf(
				t,
				free_err == .None,
				"stress free failed at op %d, kind=%v",
				op,
				slot.kind,
			)

			slot.ptr = nil
			slot.live = false
		}
	}

	// Cleanup remaining live allocations.
	for &slot in slots {
		if slot.live {
			testing.expectf(
				t,
				stress_check_allocation(slot.ptr, slot.kind, slot.seed),
				"final cleanup detected corrupted allocation, kind=%v",
				slot.kind,
			)

			free_err := free(slot.ptr, allocator)
			testing.expect_value(t, free_err, mem.Allocator_Error.None)
		}
	}
}

//
// 8. Mixed resize stress test
//
test_allocator_randomized_resize_stress :: proc(t: ^testing.T, allocator: mem.Allocator) {
	buf, err := mem.alloc_bytes(64, 16, allocator)
	if !expect_alloc_ok(t, buf, err, "resize stress initial allocation failed") {
		return
	}

	defer {
		if len(buf) > 0 {
			_ = mem.free_bytes(buf, allocator)
		}
	}

	rng := t.seed ~ 0x9E3779B97F4A7C15
	seed: u8 = 0x5A
	fill_pattern(buf, seed)

	for op := 0; op < 1000; op += 1 {
		old_len := len(buf)
		new_len := 1 + rand_range(&rng, 4096)

		resized, resize_err := mem.resize_bytes(buf, new_len, 16, allocator)
		if resize_err != .None || len(resized) != new_len {
			testing.expectf(t, false, "resize stress failed at op %d", op)
			return
		}

		preserved := min(old_len, new_len)
		testing.expectf(
			t,
			check_pattern(resized[:preserved], seed),
			"resize stress failed to preserve data at op %d",
			op,
		)

		buf = resized
		seed = u8(rand_range(&rng, 256))
		fill_pattern(buf, seed)
	}
}

THREAD_COUNT :: 8
THREAD_OPS :: 3000

Thread_Stress_Result :: struct {
	ok:           bool,
	failed_op:    int,
	failure_code: int,
}

Thread_Stress_Args :: struct {
	allocator:    mem.Allocator,
	thread_index: int,
	seed:         u64,
	result:       ^Thread_Stress_Result,
}

/*
1  Allocation failed unexpectedly
2  Alignment violation
3  Live allocation validation failed
4  Free failed
5  Replacement free failed
6  Replacement allocation failed
7  Replacement alignment violation
8  Final live allocation validation failed
9  Final cleanup free failed
*/
thread_allocator_stress_worker :: proc(args: Thread_Stress_Args) {
	SLOT_COUNT :: 64

	slots := [SLOT_COUNT]Stress_Slot{}
	rng := args.seed

	args.result.ok = true
	args.result.failed_op = -1
	args.result.failure_code = 0

	alignments := [?]int{1, 2, 4, 8, 16, 32, 64}

	for op := 0; op < THREAD_OPS; op += 1 {
		index := rand_range(&rng, SLOT_COUNT)
		slot := &slots[index]

		// Encourage more thread interleavings.
		if (next_u64(&rng) & 7) == 0 {
			thread.yield()
		}

		if !slot.live {
			kind := Stress_Kind(rand_range(&rng, STRESS_KIND_COUNT))
			alignment := alignments[rand_range(&rng, len(alignments))]

			ptr, err := stress_alloc_typed(kind, alignment, args.allocator)
			if err != .None || ptr == nil {
				args.result.ok = false
				args.result.failed_op = op
				args.result.failure_code = 1
				return
			}

			if !mem.is_aligned(ptr, alignment) {
				args.result.ok = false
				args.result.failed_op = op
				args.result.failure_code = 2
				_ = free(ptr, args.allocator)
				return
			}

			seed := u8(rand_range(&rng, 256))
			stress_init_allocation(ptr, kind, seed)

			slot.ptr = ptr
			slot.kind = kind
			slot.seed = seed
			slot.live = true
			slot.alignment = alignment
		} else {
			if !stress_check_allocation(slot.ptr, slot.kind, slot.seed) {
				args.result.ok = false
				args.result.failed_op = op
				args.result.failure_code = 3
				return
			}

			action := rand_range(&rng, 3)

			switch action {
			case 0:
				free_err := free(slot.ptr, args.allocator)
				if free_err != .None {
					args.result.ok = false
					args.result.failed_op = op
					args.result.failure_code = 4
					return
				}

				slot.ptr = nil
				slot.live = false

			case 1, 2:
				// Type churn:
				// free an existing live allocation, then allocate a possibly
				// different kind of type in its place.
				free_err := free(slot.ptr, args.allocator)
				if free_err != .None {
					args.result.ok = false
					args.result.failed_op = op
					args.result.failure_code = 5
					return
				}

				slot.ptr = nil
				slot.live = false

				new_kind := Stress_Kind(rand_range(&rng, STRESS_KIND_COUNT))
				new_alignment := alignments[rand_range(&rng, len(alignments))]

				new_ptr, alloc_err := stress_alloc_typed(new_kind, new_alignment, args.allocator)
				if alloc_err != .None || new_ptr == nil {
					args.result.ok = false
					args.result.failed_op = op
					args.result.failure_code = 6
					return
				}

				if !mem.is_aligned(new_ptr, new_alignment) {
					args.result.ok = false
					args.result.failed_op = op
					args.result.failure_code = 7
					_ = free(new_ptr, args.allocator)
					return
				}

				new_seed := u8(rand_range(&rng, 256))
				stress_init_allocation(new_ptr, new_kind, new_seed)

				slot.ptr = new_ptr
				slot.kind = new_kind
				slot.seed = new_seed
				slot.live = true
				slot.alignment = new_alignment
			}
		}
	}

	// Final validation and cleanup.
	for &slot in slots {
		if slot.live {
			if !stress_check_allocation(slot.ptr, slot.kind, slot.seed) {
				args.result.ok = false
				args.result.failed_op = THREAD_OPS
				args.result.failure_code = 8
				return
			}

			free_err := free(slot.ptr, args.allocator)
			if free_err != .None {
				args.result.ok = false
				args.result.failed_op = THREAD_OPS
				args.result.failure_code = 9
				return
			}
		}
	}
}

test_allocator_thread_safety_stress :: proc(t: ^testing.T, allocator: mem.Allocator) {
	results: [THREAD_COUNT]Thread_Stress_Result
	threads: [THREAD_COUNT]^thread.Thread

	for i := 0; i < THREAD_COUNT; i += 1 {
		args := Thread_Stress_Args {
			allocator    = allocator,
			thread_index = i,
			seed         = t.seed ~ u64(i * 0x9E3779B9),
			result       = &results[i],
		}

		threads[i] = thread.create_and_start_with_poly_data(args, thread_allocator_stress_worker)
	}

	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	for i := 0; i < THREAD_COUNT; i += 1 {
		result := results[i]

		testing.expectf(
			t,
			result.ok,
			"thread safety stress failed: thread=%d, op=%d, failure_code=%d",
			i,
			result.failed_op,
			result.failure_code,
		)
	}
}


//
// Hook the generic suite to a specific allocator.
// This example runs against the default context allocator.
//

@(test)
baseline_allocator_basic :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_basic(t, context.allocator)
}

@(test)
baseline_allocator_zeroed_alloc :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_zeroed_alloc(t, context.allocator)
}

@(test)
baseline_allocator_alignment :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_alignment(t, context.allocator)
}

@(test)
baseline_allocator_pattern_fill :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_pattern_fill(t, context.allocator)
}

@(test)
baseline_allocator_resize_grow :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_resize_grow(t, context.allocator)
}

@(test)
baseline_allocator_resize_shrink :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_resize_shrink(t, context.allocator)
}

@(test)
baseline_allocator_randomized_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_randomized_stress(t, context.allocator)
}

@(test)
baseline_allocator_randomized_resize_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_randomized_resize_stress(t, context.allocator)
}

@(test)
baseline_allocator_thread_safety_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_thread_safety_stress(t, context.allocator)
}

@(test)
default_allocator_basic :: proc(t: ^testing.T) {
	test_allocator_basic(t, context.allocator)
}

@(test)
default_allocator_zeroed_alloc :: proc(t: ^testing.T) {
	test_allocator_zeroed_alloc(t, context.allocator)
}

@(test)
default_allocator_alignment :: proc(t: ^testing.T) {
	test_allocator_alignment(t, context.allocator)
}

@(test)
default_allocator_pattern_fill :: proc(t: ^testing.T) {
	test_allocator_pattern_fill(t, context.allocator)
}

@(test)
default_allocator_resize_grow :: proc(t: ^testing.T) {
	test_allocator_resize_grow(t, context.allocator)
}

@(test)
default_allocator_resize_shrink :: proc(t: ^testing.T) {
	test_allocator_resize_shrink(t, context.allocator)
}

@(test)
default_allocator_randomized_stress :: proc(t: ^testing.T) {
	test_allocator_randomized_stress(t, context.allocator)
}

@(test)
default_allocator_randomized_resize_stress :: proc(t: ^testing.T) {
	test_allocator_randomized_resize_stress(t, context.allocator)
}

@(test)
default_allocator_thread_safety_stress :: proc(t: ^testing.T) {
	test_allocator_thread_safety_stress(t, runtime.heap_allocator())
}

@(test)
hardened_allocator_basic :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	hardened_alloc.hardened_allocator_init(&all, validate_allocator = false)
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	test_allocator_basic(t, context.allocator)
}

@(test)
hardened_allocator_zeroed_alloc :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	hardened_alloc.hardened_allocator_init(&all, validate_allocator = false)
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	test_allocator_zeroed_alloc(t, context.allocator)
}

@(test)
hardened_allocator_alignment :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	hardened_alloc.hardened_allocator_init(&all, validate_allocator = false)
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	test_allocator_alignment(t, context.allocator)
}

@(test)
hardened_allocator_pattern_fill :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	hardened_alloc.hardened_allocator_init(&all, validate_allocator = false)
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	test_allocator_pattern_fill(t, context.allocator)
}

@(test)
hardened_allocator_randomized_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	hardened_alloc.hardened_allocator_init(&all, validate_allocator = false)
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	test_allocator_randomized_stress(t, context.allocator)
}

@(test)
hardened_allocator_manual_registry_randomized_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	manual_registry: hardened_alloc.Manual_Type_Registry = {
		type_entries       = {
			hardened_alloc.manual_entry(Stress_Pointer_Block, .Pointer_Containing),
			hardened_alloc.manual_entry(Stress_Mixed_Block, .Opaque),
			hardened_alloc.manual_entry(Stress_Procedure_Block, .Procedure_Containing),
			hardened_alloc.manual_entry(Stress_Data_Block, .Data),
		},
		fallback_class     = .Opaque,
		use_fallback_class = false,
	}
	hardened_alloc.hardened_allocator_init(
		&all,
		type_policy = hardened_alloc.Type_Class_Policy.Manual_Registry,
		manual_type_registry = manual_registry,
		validate_allocator = false,
	)
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	test_allocator_randomized_stress(t, context.allocator)
}

@(test)
hardened_allocator_manual_registry_fallback_randomized_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	manual_registry: hardened_alloc.Manual_Type_Registry = {
		type_entries       = {
			hardened_alloc.manual_entry(Stress_Pointer_Block, .Pointer_Containing),
			hardened_alloc.manual_entry(Stress_Procedure_Block, .Procedure_Containing),
			hardened_alloc.manual_entry(Stress_Data_Block, .Data),
		},
		fallback_class     = .Opaque,
		use_fallback_class = true,
	}
	hardened_alloc.hardened_allocator_init(
		&all,
		type_policy = hardened_alloc.Type_Class_Policy.Manual_Registry,
		manual_type_registry = manual_registry,
		validate_allocator = false,
	)
	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	test_allocator_randomized_stress(t, context.allocator)
}

@(test)
hardened_allocator_manual_registry_failure_randomized_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	manual_registry: hardened_alloc.Manual_Type_Registry = {
		type_entries       = {
			hardened_alloc.manual_entry(Stress_Pointer_Block, .Pointer_Containing),
			hardened_alloc.manual_entry(Stress_Procedure_Block, .Procedure_Containing),
			hardened_alloc.manual_entry(Stress_Data_Block, .Data),
		},
		fallback_class     = .Opaque,
		use_fallback_class = false,
	}
	hardened_alloc.hardened_allocator_init(
		&all,
		type_policy = hardened_alloc.Type_Class_Policy.Manual_Registry,
		manual_type_registry = manual_registry,
		validate_allocator = false,
	)

	defer hardened_alloc.hardened_allocator_destroy(&all)
	context.allocator = hardened_alloc.hardened_allocator(&all)

	test_allocator_randomized_stress(t, context.allocator, &all)
}

@(test)
hardened_allocator_thread_safety_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	hardened_alloc.hardened_allocator_init(&all, validate_allocator = false)
	defer hardened_alloc.hardened_allocator_destroy(&all)

	test_allocator_thread_safety_stress(t, hardened_alloc.hardened_allocator(&all))
}

@(test)
hardened_allocator_validation_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Hardened_Allocator
	hardened_alloc.hardened_allocator_init(&all, validate_allocator = true)
	defer hardened_alloc.hardened_allocator_destroy(&all)

	test_allocator_thread_safety_stress(t, hardened_alloc.hardened_allocator(&all))
}
