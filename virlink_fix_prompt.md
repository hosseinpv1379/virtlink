
# Virlink Bandwidth Optimization & Debugging

## Context

This Go project implements virtual links between two servers using 11 different userspace protocols:

1. ICMP, 2. UDP, 3. BIP, 4. TCP, 5. TCPMUX, 6. OpenVPN, 7. OpenVPN-Multi, 8. Hysteria2, 9. WireGuard, 10. AmneziaWG, 11. UDP-Obfs

**Current Problem:** These protocols experience significant bandwidth limitations and throughput degradation.

## Task

### Phase 1: Code Inspection & Analysis

1. Read and analyze the entire codebase starting from:

   - `virlink/internal/virlink/setup.go`

   - All protocol handler files (icmp.go, udp.go, tcp.go, wireguard.go, etc.)

   - Transport/packet processing logic

   - Buffer management code

   - Flow multiplexing logic (especially tcpmux)

2. Identify bottlenecks:

   - Memory allocation/deallocation patterns (GC pressure)

   - Lock contention (mutex hot paths)

   - Buffer copying overhead

   - Inefficient packet processing loops

   - Context switching overhead

   - Goroutine spawn limits

   - Channel buffering issues

   - Syscall overhead in userspace tunnels

3. For each protocol, document:

   - Current throughput limitations

   - Which code sections cause bandwidth loss

   - Why (root cause analysis)

### Phase 2: Optimization & Refactoring

Fix identified issues:

- Use sync.Pool for buffer reuse instead of repeated allocations

- Replace contended mutexes with lock-free data structures or atomic operations where possible

- Batch packet processing instead of single-packet handling

- Increase channel buffers for high-throughput protocols

- Pre-allocate slices with correct capacity

- Reduce goroutine spawning (use worker pools)

- Optimize hot paths with assembly or cgo if needed

- Reduce syscall frequency (e.g., batch sendto/recvfrom calls)

- Profile and eliminate unnecessary data copies

### Phase 3: Preserve Logic

- Keep all protocol implementations intact

- Do NOT change API signatures or public interfaces

- Do NOT remove features or error handling

- Do NOT refactor into different design patterns

- Only optimize internal implementation

## Output

1. Detailed analysis document listing all issues found

2. Optimized code with inline comments explaining changes

3. Before/after performance comparison (if possible)

4. Priority list of fixes by impact

## Rules

- Maintain backward compatibility

- Keep code readable and maintainable

- Document any new dependencies (if added)

- Focus on bandwidth/throughput improvements

- No feature removal or major rewrites

