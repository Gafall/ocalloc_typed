package allocator_tests

import "../hardened_alloc"
import "core:mem"
import "core:testing"
import "base:runtime"
import "core:thread"

// Tests were generated with the help of ChatGPT
// https://chatgpt.com/s/t_6a040a670be88191b68fd3ff53e8210f

//
// Small deterministic RNG for randomized stress tests.
// Seed it with t.seed so failing runs are reproducible.
//
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
	buf, err := mem.alloc_bytes(128, mem.DEFAULT_ALIGNMENT, allocator)
	if !expect_alloc_ok(t, buf, err, "basic allocation failed") {
		return
	}

	testing.expect_value(t, len(buf), 128)

	free_err := mem.free_bytes(buf, allocator)
	testing.expect_value(t, free_err, mem.Allocator_Error.None)
}

//
// 2. Zero-initialization behavior for normal alloc_bytes
//
test_allocator_zeroed_alloc :: proc(t: ^testing.T, allocator: mem.Allocator) {
	buf, err := mem.alloc_bytes(256, mem.DEFAULT_ALIGNMENT, allocator)
	if !expect_alloc_ok(t, buf, err, "zeroed allocation failed") {
		return
	}
	defer mem.free_bytes(buf, allocator)

	testing.expect(t, mem.check_zero(buf), "alloc_bytes was expected to return zeroed memory")
}

//
// 3. Alignment coverage
//
test_allocator_alignment :: proc(t: ^testing.T, allocator: mem.Allocator) {
	alignments := [?]int{1, 2, 4, 8, 16, 32, 64, 128}

	for alignment in alignments {
		buf, err := mem.alloc_bytes(257, alignment, allocator)
		if !expect_alloc_ok(t, buf, err, "aligned allocation failed") {
			continue
		}

		ptr := rawptr(raw_data(buf))
		testing.expectf(
			t,
			mem.is_aligned(ptr, alignment),
			"allocation was not aligned to %d bytes",
			alignment,
		)

		free_err := mem.free_bytes(buf, allocator)
		testing.expect_value(t, free_err, mem.Allocator_Error.None)
	}
}

//
// 4. Pattern-fill correctness
//
test_allocator_pattern_fill :: proc(t: ^testing.T, allocator: mem.Allocator) {
	buf, err := mem.alloc_bytes(1024, 16, allocator)
	if !expect_alloc_ok(t, buf, err, "pattern allocation failed") {
		return
	}
	defer mem.free_bytes(buf, allocator)

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
Stress_Slot :: struct {
	data: []u8,
	seed: u8,
	live: bool,
	alignment: int
}

test_allocator_randomized_stress :: proc(t: ^testing.T, allocator: mem.Allocator) {
	SLOT_COUNT :: 512
	OPS :: 5000000

	slots := [SLOT_COUNT]Stress_Slot{}
	rng := t.seed

	for op := 0; op < OPS; op += 1 {
		index := rand_range(&rng, SLOT_COUNT)
		slot := &slots[index]

		if !slot.live {
			size := 1 + rand_range(&rng, 2048)
			alignments := [?]int{1, 2, 4, 8, 16, 32, 64}
			alignment := alignments[rand_range(&rng, len(alignments))]

			buf, err := mem.alloc_bytes(size, alignment, allocator)
			if err != .None || len(buf) != size {
				testing.expectf(
					t,
					false,
					"stress alloc failed at op %d, size=%d, alignment=%d",
					op,
					size,
					alignment,
				)
				continue
			}

			ptr := rawptr(raw_data(buf))
			testing.expectf(
				t,
				mem.is_aligned(ptr, alignment),
				"stress allocation alignment failed at op %d",
				op,
			)

			seed := u8(rand_range(&rng, 256))
			fill_pattern(buf, seed)

			slot.data = buf
			slot.seed = seed
			slot.live = true
			slot.alignment = alignment
		} else {
			testing.expectf(
				t,
				check_pattern(slot.data, slot.seed),
				"stress pattern corruption detected at op %d",
				op,
			)

			free_err := mem.free_bytes(slot.data, allocator)
			testing.expectf(t, free_err == .None, "stress free failed at op %d", op)

			slot.data = nil
			slot.live = false
		}
	}

	// Cleanup remaining live allocations.
	for &slot in slots {
		if slot.live {
			testing.expect(
				t,
				check_pattern(slot.data, slot.seed),
				"final cleanup detected corrupted pattern",
			)

			free_err := mem.free_bytes(slot.data, allocator)
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
THREAD_OPS  :: 3000

Thread_Stress_Result :: struct {
	ok: bool,
	failed_op: int,
	failure_code: int,
}

Thread_Stress_Args :: struct {
	allocator: mem.Allocator,
	thread_index: int,
	seed: u64,
	result: ^Thread_Stress_Result,
}

thread_allocator_stress_worker :: proc(args: Thread_Stress_Args) {
	SLOT_COUNT :: 64

	slots:= [SLOT_COUNT]Stress_Slot{}
	rng := args.seed

	args.result.ok = true
	args.result.failed_op = -1
	args.result.failure_code = 0

	for op := 0; op < THREAD_OPS; op += 1 {
		index := rand_range(&rng, SLOT_COUNT)
		slot := &slots[index]

		// Encourage more thread interleavings.
		if (next_u64(&rng) & 7) == 0 {
			thread.yield()
		}

		if !slot.live {
			size := 1 + rand_range(&rng, 4096)
			alignments := [?]int{1, 2, 4, 8, 16, 32, 64}
			alignment := alignments[rand_range(&rng, len(alignments))]

			buf, err := mem.alloc_bytes(size, alignment, args.allocator)
			if err != .None || len(buf) != size {
				args.result.ok = false
				args.result.failed_op = op
				args.result.failure_code = 1
				return
			}

			ptr := rawptr(raw_data(buf))
			if !mem.is_aligned(ptr, alignment) {
				args.result.ok = false
				args.result.failed_op = op
				args.result.failure_code = 2
				_ = mem.free_bytes(buf, args.allocator)
				return
			}

			seed := u8(rand_range(&rng, 256))
			fill_pattern(buf, seed)

			slot.data = buf
			slot.seed = seed
			slot.live = true
			slot.alignment = alignment
		} else {
			if !check_pattern(slot.data, slot.seed) {
				args.result.ok = false
				args.result.failed_op = op
				args.result.failure_code = 3
				return
			}

			action := rand_range(&rng, 3)

			switch action {
			case 0:
				free_err := mem.free_bytes(slot.data, args.allocator)
				if free_err != .None {
					args.result.ok = false
					args.result.failed_op = op
					args.result.failure_code = 4
					return
				}

				slot.data = nil
				slot.live = false

			case 1, 2:
				old_len := len(slot.data)
				new_len := 1 + rand_range(&rng, 4096)

				resized, resize_err := mem.resize_bytes(
					slot.data,
					new_len,
					slot.alignment,
					args.allocator,
				)

				if resize_err != .None || len(resized) != new_len {
					args.result.ok = false
					args.result.failed_op = op
					args.result.failure_code = 5
					return
				}

				preserved := min(old_len, new_len)
				if !check_pattern(resized[:preserved], slot.seed) {
					args.result.ok = false
					args.result.failed_op = op
					args.result.failure_code = 6
					return
				}

				slot.data = resized
				slot.seed = u8(rand_range(&rng, 256))
				fill_pattern(slot.data, slot.seed)
			}
		}
	}

	// Final validation and cleanup.
	for &slot in slots {
		if slot.live {
			if !check_pattern(slot.data, slot.seed) {
				args.result.ok = false
				args.result.failed_op = THREAD_OPS
				args.result.failure_code = 7
				return
			}

			free_err := mem.free_bytes(slot.data, args.allocator)
			if free_err != .None {
				args.result.ok = false
				args.result.failed_op = THREAD_OPS
				args.result.failure_code = 8
				return
			}
		}
	}
}

test_allocator_thread_safety_stress :: proc(
	t: ^testing.T,
	allocator: mem.Allocator,
) {
	results: [THREAD_COUNT]Thread_Stress_Result
	threads: [THREAD_COUNT]^thread.Thread

	for i := 0; i < THREAD_COUNT; i += 1 {
		args := Thread_Stress_Args{
			allocator = allocator,
			thread_index = i,
			seed = t.seed ~ u64(i * 0x9E3779B9),
			result = &results[i],
		}

		threads[i] = thread.create_and_start_with_poly_data(
			args,
			thread_allocator_stress_worker,
		)
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
default_allocator_basic :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all, context.allocator)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_basic(t, context.allocator)
}

@(test)
default_allocator_zeroed_alloc :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all, context.allocator)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_zeroed_alloc(t, context.allocator)
}

@(test)
default_allocator_alignment :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all, context.allocator)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_alignment(t, context.allocator)
}

@(test)
default_allocator_pattern_fill :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all, context.allocator)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_pattern_fill(t, context.allocator)
}

@(test)
default_allocator_resize_grow :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all, context.allocator)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_resize_grow(t, context.allocator)
}

@(test)
default_allocator_resize_shrink :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all, context.allocator)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_resize_shrink(t, context.allocator)
}

@(test)
default_allocator_randomized_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all, context.allocator)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_randomized_stress(t, context.allocator)
}

@(test)
default_allocator_randomized_resize_stress :: proc(t: ^testing.T) {
	all: hardened_alloc.Segregated_Free_List
	hardened_alloc.segregated_free_list_init(&all, context.allocator)
	defer hardened_alloc.segregated_free_list_destroy(&all)
	context.allocator = hardened_alloc.segregated_free_list_allocator(&all)

	test_allocator_randomized_resize_stress(t, context.allocator)
}

@(test)
default_allocator_thread_safety_stress :: proc(t: ^testing.T) {
	
	test_allocator_thread_safety_stress(t, runtime.heap_allocator())
}