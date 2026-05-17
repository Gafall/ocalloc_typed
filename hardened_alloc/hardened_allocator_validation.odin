package hardened_alloc

import "base:runtime"
import "core:crypto"
import "core:crypto/blake2b"
import "core:slice"
import "core:sync"


hardened_allocator_init_secrets :: proc(secrets: ^Hardened_Allocator_Secrets) {
	crypto.rand_bytes(secrets.allocation_header_key[:])
	crypto.rand_bytes(secrets.free_block_key[:])
	crypto.rand_bytes(secrets.metadata_key[:])
	crypto.rand_bytes(secrets.region_key[:])
	crypto.rand_bytes(secrets.zone_key[:])
	secrets.type_class_seed = 0
	secrets.validate_allocator = false
}

hardened_allocator_tag_allocation_header :: proc(
	header: ^Hardened_Allocator_Allocation_Header,
	secrets: ^Hardened_Allocator_Secrets,
) {
	if !secrets.validate_allocator {
		return
	}
	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.allocation_header_key[:], size_of(header.tag))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(header, int(offset_of(Hardened_Allocator_Allocation_Header, tag)))[:],
	)
	blake2b.final(&ctx, header.tag[:])
}


@(require_results)
hardened_allocator_validate_allocation_header :: proc(
	header: ^Hardened_Allocator_Allocation_Header,
	secrets: ^Hardened_Allocator_Secrets,
) -> bool {
	if !secrets.validate_allocator {
		return true
	}
	expected: [16]u8

	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.allocation_header_key[:], len(expected))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(header, int(offset_of(Hardened_Allocator_Allocation_Header, tag)))[:],
	)
	blake2b.final(&ctx, expected[:])

	return crypto.compare_constant_time(expected[:], header.tag[:]) == 1
}

hardened_allocator_tag_free_block :: proc(
	block: ^Hardened_Allocator_Free_Block,
	secrets: ^Hardened_Allocator_Secrets,
) {
	if !secrets.validate_allocator {
		return
	}
	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.free_block_key[:], size_of(block.tag))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(block, int(offset_of(Hardened_Allocator_Free_Block, tag)))[:],
	)
	blake2b.final(&ctx, block.tag[:])
}

@(require_results)
hardened_allocator_validate_free_block :: proc(
	block: ^Hardened_Allocator_Free_Block,
	secrets: ^Hardened_Allocator_Secrets,
) -> bool {
	if !secrets.validate_allocator {
		return true
	}
	expected: [16]u8

	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.free_block_key[:], len(expected))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(block, int(offset_of(Hardened_Allocator_Free_Block, tag)))[:],
	)
	blake2b.final(&ctx, expected[:])

	return crypto.compare_constant_time(expected[:], block.tag[:]) == 1
}


hardened_allocator_tag_metadata :: proc(
	metadata: ^Hardened_Allocator_Metadata,
	secrets: ^Hardened_Allocator_Secrets,
) {
	if !secrets.validate_allocator {
		return
	}
	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.metadata_key[:], size_of(metadata.tag))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(metadata, int(offset_of(Hardened_Allocator_Metadata, tag)))[:],
	)
	blake2b.final(&ctx, metadata.tag[:])
}

@(require_results)
hardened_allocator_validate_metadata :: proc(
	metadata: ^Hardened_Allocator_Metadata,
	secrets: ^Hardened_Allocator_Secrets,
) -> bool {
	if !secrets.validate_allocator {
		return true
	}
	expected: [16]u8

	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.metadata_key[:], len(expected))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(metadata, int(offset_of(Hardened_Allocator_Metadata, tag)))[:],
	)
	blake2b.final(&ctx, expected[:])

	return crypto.compare_constant_time(expected[:], metadata.tag[:]) == 1
}

hardened_allocator_tag_region :: proc(
	region: ^Hardened_Allocator_Region,
	secrets: ^Hardened_Allocator_Secrets,
) {
	if !secrets.validate_allocator {
		return
	}
	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.region_key[:], size_of(region.tag))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(region, int(offset_of(Hardened_Allocator_Region, tag)))[:],
	)
	blake2b.final(&ctx, region.tag[:])
}

@(require_results)
hardened_allocator_validate_region :: proc(
	region: ^Hardened_Allocator_Region,
	secrets: ^Hardened_Allocator_Secrets,
) -> bool {
	if !secrets.validate_allocator {
		return true
	}
	expected: [16]u8

	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.region_key[:], len(expected))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(region, int(offset_of(Hardened_Allocator_Region, tag)))[:],
	)
	blake2b.final(&ctx, expected[:])

	return crypto.compare_constant_time(expected[:], region.tag[:]) == 1
}

hardened_allocator_tag_zone :: proc(
	zone: ^Hardened_Allocator_Zone,
	secrets: ^Hardened_Allocator_Secrets,
) {
	if !secrets.validate_allocator {
		return
	}
	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.zone_key[:], size_of(zone.tag))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(zone, int(offset_of(Hardened_Allocator_Zone, tag)))[:],
	)
	blake2b.final(&ctx, zone.tag[:])
}

@(require_results)
hardened_allocator_validate_zone :: proc(
	zone: ^Hardened_Allocator_Zone,
	secrets: ^Hardened_Allocator_Secrets,
) -> bool {
	if !secrets.validate_allocator {
		return true
	}
	expected: [16]u8

	ctx: blake2b.Context
	blake2b.init_mac(&ctx, secrets.zone_key[:], len(expected))
	blake2b.update(
		&ctx,
		slice.bytes_from_ptr(zone, int(offset_of(Hardened_Allocator_Zone, tag)))[:],
	)
	blake2b.final(&ctx, expected[:])

	return crypto.compare_constant_time(expected[:], zone.tag[:]) == 1
}

hardened_allocator_check_zone :: proc(
	zone: ^Hardened_Allocator_Zone,
	secrets: ^Hardened_Allocator_Secrets,
) {
	sync.mutex_guard(&zone.tag_mutex)

	if !hardened_allocator_validate_zone(zone, secrets) {
		panic("Allocator zone has been corrupted")
	}
}
