package main

// Note: this requires compiling on the same arch as the binary to be examined,
// to get pointer size and endianness right.

import (
	"debug/elf"
	"debug/macho"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Println("Usage:")
		fmt.Println()
		fmt.Println("    dumpgc <binary> [<function>]")
		fmt.Println()
		fmt.Println("Dumps garbage collection information about the functions")
		fmt.Println("in the given binary, or the one specific function if given.")
		fmt.Println("This tool must be built for the same architecture that")
		fmt.Println("the binary was built.")
		os.Exit(1)
	}
	file := os.Args[1]
	var funcName string
	if len(os.Args) > 2 {
		funcName = os.Args[2]
	}

	// Open binary (aka inferior).
	// Save reference to inferior for reflect-like accessors.
	if runtime.GOOS == "darwin" {
		f, err := macho.Open(file)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		inferior = &inferiorMacho{f: f, sectionCache: map[int][]byte{}}
	} else {
		f, err := elf.Open(file)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		inferior = &inferiorElf{f: f, sectionCache: map[int][]byte{}}
	}
	// TODO: pe?

	// Read the root from which we find all GC info.
	m := getSymbol[moduledata]("runtime.firstmoduledata").deref()

	// Loop over all the functions.
	// (The last entry is a dummy with its entryoff marking the end of Go code.)
	for i := uintptr(0); i < m.ftab.len-1; i++ {
		ftabEntry := m.ftab.elem(i)
		fp := cast[*byte, *_func](m.pclntable.elemAddr(uintptr(ftabEntry.funcoff)))
		if funcName != "" && fp.deref().name(m) != funcName { // Filter on function name.
			continue
		}
		printFunc(fp, m)
	}
}

func printFunc(fp pointer[_func], m moduledata) {
	f := fp.deref()
	entry := m.text + uintptr(f.entryOff)
	name := f.name(m)
	fmt.Printf("function: %s\n", name)
	fmt.Printf("\tentry: %x\n", entry)
	if f.args != 0 { // TODO: sometimes 0x80000000? never used?
		fmt.Printf("\targbytes: %d\n", f.args)
	}
	if f.deferreturn != 0 {
		fmt.Printf("\tdeferreturn entry: %x\n", entry+uintptr(f.deferreturn))
	}

	// pcsp, encodes stack frame size at every pc
	var frameSize uintptr
	if f.pcsp != 0 {
		p := m.pctab.elemAddr(uintptr(f.pcsp))
		data := decodepcData(entry, p)
		for _, e := range data {
			frameSize = max(frameSize, uintptr(e.val))
		}
		fmt.Printf("\tframe size: %d\n", frameSize)
		if frameSize > 0 {
			for _, e := range data {
				fmt.Printf("\t\t[%x:%x]: %d\n", e.min, e.max-1, e.val)
			}
		}
	}

	// Locations which are safe for async preemption.
	if p := pcdata(fp, abi_PCDATA_UnsafePoint, m); p != 0 {
		data := decodepcData(entry, p)
		if !(len(data) == 1 && data[0].val == abi_UnsafePointSafe) {
			fmt.Printf("\tpreempt safety:\n")
			for _, e := range data {
				var s string
				switch e.val {
				case abi_UnsafePointSafe:
					s = "safe"
				case abi_UnsafePointUnsafe:
					s = "unsafe"
				case abi_UnsafePointRestart1:
					s = "restart1"
				case abi_UnsafePointRestart2:
					s = "restart2"
				case abi_UnsafePointRestartAtEntry:
					s = "restart at entry"
				default:
					s = fmt.Sprintf("%d", e.val)
				}
				fmt.Printf("\t\t[%x:%x]: %s\n", e.min, e.max-1, s)

			}
		}
	}

	// Figure out offsets of arg and local sections from the stack pointer
	// (when the frame is fully allocated).
	// This helps correlate the live slots with offsets in assembly dumps.
	argp := frameSize
	varp := frameSize
	switch runtime.GOARCH {
	case "amd64", "386":
		// |                   |
		// |  incoming args    |
		// +-------------------+  <- argp, caller SP
		// |  return address   |
		// +-------------------+                ---
		// |    saved FP       |                 ^
		// +-------------------+  <- FP, varp    |
		// |                   |                 |
		// | pointer-y locals  |                 |
		// |                   |
		// +-------------------+                 frameSize
		// |                   |
		// |   other locals    |                 |
		// |                   |                 |
		// +-------------------+                 |
		// |  outgoing args    |                 v
		// +-------------------+   <- SP        ---

		argp += ptrSize // return address
		varp -= ptrSize // frame pointer
	case "arm64":
		// |                   |
		// |  incoming args    |
		// +-------------------+  <- argp
		// | caller's retaddr  |
		// +-------------------+  <- caller SP  ---
		// | caller's saved FP |                 ^
		// +-------------------+  <- varp        |
		// |                   |                 |
		// | pointer-y locals  |                 |
		// |                   |                 |
		// +-------------------+
		// |                   |                 frameSize
		// |   other locals    |
		// |                   |                 |
		// +-------------------+                 |
		// |  outgoing args    |                 |
		// +-------------------+                 |
		// |  return address   |                 v
		// +-------------------+   <- SP        ---
		// |   saved FP        |
		// +-------------------+   <- FP
		argp += ptrSize
		varp -= ptrSize // skil over caller's FP save area
	default:
		panic("TODO")
	}

	// Pointer maps.
	var argMaps []string
	if p := funcdata(fp, abi_FUNCDATA_ArgsPointerMaps, m); p != 0 {
		args := cast[*byte, *stackmap](p).deref()
		nbyte := (args.nbit + 7) / 8
		for i := int32(0); i < args.n; i++ {
			b := bitmask{
				n: uintptr(args.nbit),
				p: p.offset(unsafe.Offsetof(stackmap{}.bytedata) + uintptr(nbyte*i)),
			}
			argMaps = append(argMaps, b.String())
		}
	}
	var localMaps []string
	var localMapSize uintptr
	if p := funcdata(fp, abi_FUNCDATA_LocalsPointerMaps, m); p != 0 {
		locals := cast[*byte, *stackmap](p).deref()
		nbyte := (locals.nbit + 7) / 8
		for i := int32(0); i < locals.n; i++ {
			b := bitmask{
				n: uintptr(locals.nbit),
				p: p.offset(unsafe.Offsetof(stackmap{}.bytedata) + uintptr(nbyte*i)),
			}
			localMaps = append(localMaps, b.String())
		}
		localMapSize = uintptr(locals.nbit) * ptrSize
	}
	if p := pcdata(fp, abi_PCDATA_StackMapIndex, m); p != 0 {
		data := decodepcData(entry, p)
		fmt.Printf("\tlive pointer maps, args@%s locals@%s:\n", spOff(argp), spOff(varp-localMapSize))
		for _, e := range data {
			idx := e.val
			if idx == -1 {
				// TODO: or select 0 instead?
				fmt.Printf("\t\t[%x:%x]: none\n", e.min, e.max-1)
				continue
			}
			fmt.Printf("\t\t[%x:%x]: args:%s locals:%s\n", e.min, e.max-1, argMaps[idx], localMaps[idx])
		}
	}

	// Stack objects
	if p := funcdata(fp, abi_FUNCDATA_StackObjects, m); p != 0 {
		n := cast[*byte, *uintptr](p).deref()
		objs := cast[*byte, *stackObjectRecord](p.offset(ptrSize)).extend(n)
		fmt.Printf("\tstack objects:\n")
		for i := uintptr(0); i < objs.len; i++ {
			obj := objs.elem(i)

			gcmask := pointer[byte](m.rodata + uintptr(obj.gcdataoff))
			n := uintptr(obj.ptrBytes) / ptrSize
			b := bitmask{n: n, p: gcmask}

			// Note: positive offsets are up from argp.
			// Negative offsets are down from varp.
			var sp uintptr
			if obj.off >= 0 {
				sp = argp + uintptr(obj.off)
			} else {
				sp = varp + uintptr(int(obj.off))
			}
			fmt.Printf("\t\t%s size:%d ptrbytes:%d, mask:%s\n", spOff(sp), obj.size, obj.ptrBytes, b.String())
		}
	}
}

// In order to better eyeball-match offsets from SP with offsets
// listed in assembly, we match what the native objdump does.
// It's annoying to have to do this, but helpful.
func spOff(x uintptr) string {
	switch runtime.GOARCH {
	case "amd64", "386":
		return fmt.Sprintf("sp+0x%x", x)
	case "arm64":
		return fmt.Sprintf("sp+%d", x)
	default:
		panic("TODO")
	}
}

// +----------------------------------------------------------------+
// | Types referring to the data in the inferior                    |
// +----------------------------------------------------------------+

// A pointer in the inferior.
type pointer[T any] uintptr

// deref computes *p for an inferior pointer p.
func (p pointer[T]) deref() T {
	var t T
	data := inferior.read(uintptr(p), unsafe.Sizeof(t))
	return *(*T)(unsafe.Pointer(&data[0]))
}

// cast converts from a *T to a *U.
// (It would be nice to make this as a method on pointer[T] parameterized by U, but we can't.)
func cast[TP *T, UP *U, T, U any](p pointer[T]) pointer[U] {
	return pointer[U](p)
}

// Add n bytes to p.
func (p pointer[T]) offset(n uintptr) pointer[T] {
	return p + (pointer[T])(n)
}

// A slice pointing to something in the inferior.
type slice[T any] struct {
	ptr pointer[T]
	len uintptr
	cap uintptr
}

func (s slice[T]) elemAddr(i uintptr) pointer[T] {
	var t T
	return (pointer[T])(uintptr(s.ptr) + i*unsafe.Sizeof(t))
}
func (s slice[T]) elem(i uintptr) T {
	return s.elemAddr(i).deref()
}

// returns s[i:]
func (s slice[T]) sliceFront(i uintptr) slice[T] {
	return slice[T]{ptr: s.elemAddr(i), len: s.len - i, cap: s.cap - i}
}

// Convert a *T to a []T of length n starting at that pointer.
func (p pointer[T]) extend(n uintptr) slice[T] {
	return slice[T]{ptr: p, len: n, cap: n}
}

type map_[K, V any] uintptr // not used, just a placeholder

// +----------------------------------------------------------------+
// | Inferior accessors                                             |
// +----------------------------------------------------------------+

type inferiorInterface interface {
	// symbol returns the address of a symbol in the inferior.
	symbol(name string) uintptr
	// read reads the data at the given inferior address and size.
	// (The read-from region cannot straddle sections.)
	read(addr, size uintptr) []byte
}

// getSymbol returns the address of a symbol in the inferior.
// The returned pointer has type *T.
func getSymbol[T any](name string) pointer[T] {
	return pointer[T](inferior.symbol(name))
}

// Global variable that contains a reference to the inferior.
// Used by accessors to get at the inferior's memory contents.
var inferior inferiorInterface

type inferiorElf struct {
	f            *elf.File
	sectionCache map[int][]byte
}

func (inf inferiorElf) symbol(name string) uintptr {
	syms, err := inf.f.Symbols()
	if err != nil {
		panic(err)
	}
	for _, sym := range syms {
		if sym.Name == name {
			return uintptr(sym.Value)
		}
	}
	panic(fmt.Sprintf("can't find symbol %s", name))
}

func (inf inferiorElf) read(addr, size uintptr) []byte {
	for i, section := range inf.f.Sections {
		if uint64(addr) >= section.Addr && uint64(addr+size) <= section.Addr+section.Size {
			var data []byte
			if d, ok := inf.sectionCache[i]; ok {
				data = d
			} else {
				d, err := section.Data()
				if err != nil {
					panic(err)
				}
				inf.sectionCache[i] = d
				data = d
			}
			return data[uint64(addr)-section.Addr:][:size]
		}
	}
	panic(fmt.Sprintf("can't find data [%x:%x] in inferior", addr, addr+size))
}

type inferiorMacho struct {
	f            *macho.File
	sectionCache map[int][]byte
}

func (inf inferiorMacho) symbol(name string) uintptr {
	syms := inf.f.Symtab.Syms
	for _, sym := range syms {
		if sym.Name == name {
			return uintptr(sym.Value)
		}
	}
	panic(fmt.Sprintf("can't find symbol %s", name))
}

func (inf inferiorMacho) read(addr, size uintptr) []byte {
	for i, section := range inf.f.Sections {
		if uint64(addr) >= section.Addr && uint64(addr+size) <= section.Addr+section.Size {
			var data []byte
			if d, ok := inf.sectionCache[i]; ok {
				data = d
			} else {
				d, err := section.Data()
				if err != nil {
					panic(err)
				}
				inf.sectionCache[i] = d
				data = d
			}
			return data[uint64(addr)-section.Addr:][:size]
		}
	}
	panic(fmt.Sprintf("can't find data [%x:%x] in inferior", addr, addr+size))
}

// +----------------------------------------------------------------+
// | This section is copied directly from the runtime (circa 1.24). |
// +----------------------------------------------------------------+

// We replace *T with pointer[T], []T with slice[T], and map[K]V with map_[K,V].

type moduledata struct {
	pcHeader     pointer[pcHeader]
	funcnametab  slice[byte]
	cutab        slice[uint32]
	filetab      slice[byte]
	pctab        slice[byte]
	pclntable    slice[byte]
	ftab         slice[functab]
	findfunctab  uintptr
	minpc, maxpc uintptr

	text, etext           uintptr
	noptrdata, enoptrdata uintptr
	data, edata           uintptr
	bss, ebss             uintptr
	noptrbss, enoptrbss   uintptr
	covctrs, ecovctrs     uintptr
	end, gcdata, gcbss    uintptr
	types, etypes         uintptr
	rodata                uintptr
	gofunc                uintptr // go.func.*

	textsectmap slice[textsect]
	typelinks   slice[int32] // offsets from types
	itablinks   slice[pointer[itab]]

	ptab slice[ptabEntry]

	pluginpath string
	pkghashes  slice[modulehash]

	// This slice records the initializing tasks that need to be
	// done to start up the program. It is built by the linker.
	inittasks slice[pointer[initTask]]

	modulename   string
	modulehashes slice[modulehash]

	hasmain uint8 // 1 if module contains the main function, 0 otherwise
	bad     bool  // module failed to load and should be ignored

	gcdatamask, gcbssmask bitvector

	typemap map_[typeOff, pointer[_type]] // offset to *_rtype in previous module

	next pointer[moduledata]
}
type bitvector struct {
	n        int32 // # of bits
	bytedata pointer[uint8]
}

type functab struct {
	entryoff uint32 // relative to runtime.text
	funcoff  uint32
}
type _func struct {
	entryOff uint32 // start pc, as offset from moduledata.text/pcHeader.textStart
	nameOff  int32  // function name, as index into moduledata.funcnametab.

	args        int32  // in/out args size
	deferreturn uint32 // offset of start of a deferreturn call instruction from entry, if any.

	pcsp      uint32
	pcfile    uint32
	pcln      uint32
	npcdata   uint32
	cuOffset  uint32     // runtime.cutab offset of this function's CU
	startLine int32      // line number of start of function (func keyword/TEXT directive)
	funcID    abi_FuncID // set for certain special runtime functions
	flag      abi_FuncFlag
	_         [1]byte // pad
	nfuncdata uint8   // must be last, must end on a uint32-aligned boundary

}
type abi_FuncID uint8
type abi_FuncFlag uint8

const (
	abi_PCDATA_UnsafePoint   = 0
	abi_PCDATA_StackMapIndex = 1

	abi_UnsafePointSafe           = -1
	abi_UnsafePointUnsafe         = -2
	abi_UnsafePointRestart1       = -3
	abi_UnsafePointRestart2       = -4
	abi_UnsafePointRestartAtEntry = -5

	abi_FUNCDATA_ArgsPointerMaps   = 0
	abi_FUNCDATA_LocalsPointerMaps = 1
	abi_FUNCDATA_StackObjects      = 2
)

type stackmap struct {
	n        int32   // number of bitmaps
	nbit     int32   // number of bits in each bitmap
	bytedata [1]byte // bitmaps, each starting on a byte boundary
}

type stackObjectRecord struct {
	// offset in frame
	// if negative, offset from varp
	// if non-negative, offset from argp
	off       int32
	size      int32
	ptrBytes  int32
	gcdataoff uint32 // offset to gcdata from moduledata.rodata
}

// types we don't care about
type pcHeader byte
type textsect byte
type itab byte
type ptabEntry byte
type modulehash byte
type initTask byte
type typeOff byte
type _type byte

// +----------------------------------------------------------------+
// | Convenience methods                                            |
// +----------------------------------------------------------------+

func readNullTerminatedString(p pointer[byte]) string {
	var s strings.Builder
	for {
		b := p.deref()
		if b == 0 {
			return s.String()
		}
		s.WriteByte(b)
		p++
	}
}

func (f _func) name(m moduledata) string {
	return readNullTerminatedString(m.funcnametab.elemAddr(uintptr(f.nameOff)))
}

// pcdata returns the address of the pcdata table tab, or 0 if none available.
func pcdata(fp pointer[_func], tab uint32, m moduledata) pointer[byte] {
	f := fp.deref()
	if tab >= f.npcdata {
		return 0
	}
	off := unsafe.Offsetof(_func{}.nfuncdata) + unsafe.Sizeof(_func{}.nfuncdata) + uintptr(tab)*4
	off2 := cast[*_func, *uint32](fp.offset(off)).deref()
	if off2 == 0 {
		return 0
	}
	return m.pctab.elemAddr(uintptr(off2))
}

// funcdata returns the address of the function data identified by idx, or 0 if none available.
func funcdata(fp pointer[_func], idx uint8, m moduledata) pointer[byte] {
	f := fp.deref()
	if idx >= f.nfuncdata {
		return 0
	}
	off := unsafe.Offsetof(_func{}.nfuncdata) + unsafe.Sizeof(_func{}.nfuncdata) + uintptr(f.npcdata)*4 + uintptr(idx)*4
	off2 := cast[*_func, *uint32](fp.offset(off)).deref()
	if off2 == ^uint32(0) {
		return 0
	}
	return pointer[byte](m.gofunc + uintptr(off2))
}

const ptrSize = unsafe.Sizeof(uintptr(0))

type bitmask struct {
	n uintptr
	p pointer[byte]
}

func (b bitmask) String() string {
	var s strings.Builder
	bytes := b.p.extend((b.n + 7) / 8)
	for i := uintptr(0); i < b.n; i++ {
		if bytes.elem(i/8)>>(i%8)&1 != 0 {
			s.WriteString("1")
		} else {
			s.WriteString("0")
		}
	}
	return s.String()
}

type pcDataEntry struct {
	min, max uintptr // pcs
	val      int32
}

func decodepcData(entry uintptr, p pointer[byte]) []pcDataEntry {
	var pcQuantum uint32
	switch runtime.GOARCH {
	case "amd64", "386", "wasm":
		pcQuantum = 1
	case "s390x":
		pcQuantum = 2
	default:
		pcQuantum = 4
	}
	var res []pcDataEntry
	val := int32(-1)
	pc := entry
	for {
		var valDelta int32
		p, valDelta = decodeVarint(p)
		if valDelta == 0 && pc != entry {
			return res
		}
		var pcDelta uint32
		p, pcDelta = decodeUvarint(p)
		pcDelta *= pcQuantum

		// The new value applies between the old pc and the new pc.
		res = append(res, pcDataEntry{min: pc, max: pc + uintptr(pcDelta), val: val + valDelta})

		val += valDelta
		pc += uintptr(pcDelta)
	}
}

func decodeVarint(p pointer[byte]) (pointer[byte], int32) {
	p, u := decodeUvarint(p)
	if u&1 != 0 { // zig-zag encoding
		return p, ^int32(u >> 1)
	}
	return p, int32(u >> 1)
}

func decodeUvarint(p pointer[byte]) (pointer[byte], uint32) {
	var v, shift uint32
	for {
		b := p.deref()
		p = p.offset(1)
		v |= uint32(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return p, v
}
