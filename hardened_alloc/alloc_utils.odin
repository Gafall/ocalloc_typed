package hardened_alloc

import "base:runtime"
import "core:mem"

Allocator :: runtime.Allocator
Allocator_Error :: runtime.Allocator_Error
Allocator_Mode :: runtime.Allocator_Mode
Allocator_Mode_Set :: runtime.Allocator_Mode_Set
Allocator_Query_Info :: runtime.Allocator_Query_Info


DEFAULT_ALIGNMENT :: mem.DEFAULT_ALIGNMENT
SIZE_CLASS_COUNT :: 32
MIN_SIZE_CLASS :: 32
MIN_SPLIT_PAYLOAD :: 16
DEFAULT_REGION_SIZE :: 64 * mem.DEFAULT_PAGE_SIZE
