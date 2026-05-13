package hardened_alloc

import "base:runtime"
import "core:mem"

Allocator :: runtime.Allocator
Allocator_Error :: runtime.Allocator_Error
Allocator_Mode :: runtime.Allocator_Mode
Allocator_Mode_Set :: runtime.Allocator_Mode_Set
Allocator_Query_Info :: runtime.Allocator_Query_Info


DEFAULT_ALIGNMENT :: mem.DEFAULT_ALIGNMENT
REGION_SIZE :: mem.DEFAULT_PAGE_SIZE
