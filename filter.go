// Package protolaser allows working with protocol buffer wire format data.
// It allows matching on specific fields without decoding the entire message.
package protolaser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

var (
	errMismatch            = errors.New("mismatch")
	ErrCorrupted           = errors.New("protobuf wire data is invalid")
	ErrLastWinsUnsupported = errors.New("the protobuf contained multiple values for a field but this is not supported by protolaser")
)

type wireType uint8

const (
	wireVarint wireType = 0
	wireI64    wireType = 1
	wireLen    wireType = 2
	wireSgroup wireType = 3
	wireEgroup wireType = 4
	wireI32    wireType = 5
)

type missingBehavior uint8

const (
	missingIsMismatch missingBehavior = iota
	missingIsMatch
	descendIfMissing
)

// MessageFilter allows filtering on protobuf wireformat data.
//
// Concurrent calls to MessageFilter are not allowed, except that Match can run safely with other Match calls.
//
// Each tag can only have one filter. Later calls overwrite earlier calls. Extracting and filtering the same field is similarly not possible. This might change in a future major version.
type MessageFilter struct {
	tagLookup       map[uint32]uint32
	filters         []filter
	missingBehavior []missingBehavior
}

func (f *MessageFilter) Submessage(tag uint32) *MessageFilter {
	idx, ok := f.tagLookup[tag]
	if !ok {
		sub := &MessageFilter{}
		f.setFilterEx(tag, sub, descendIfMissing)
		return sub
	}
	s, ok := f.filters[idx].(*MessageFilter)
	if !ok {
		panic(fmt.Errorf("protolaser: Submessage(%d) called, but another filter type is already configured for field tag %d", tag, tag))
	}
	return s
}

func (f *MessageFilter) Internal__CustomMessageFilter(tag uint32, sub filter) {
	f.setFilterEx(tag, sub, descendIfMissing)
}

func (f *MessageFilter) Internal__GetFilter(tag uint32) filter {
	idx, ok := f.tagLookup[tag]
	if !ok {
		return nil
	}
	return f.filters[idx]
}

func (f *MessageFilter) setFilterEx(tag uint32, sub filter, missingBehavior missingBehavior) {
	if f.tagLookup == nil {
		f.tagLookup = map[uint32]uint32{}
	}
	f.tagLookup[tag] = uint32(len(f.filters))
	f.filters = append(f.filters, sub)
	f.missingBehavior = append(f.missingBehavior, missingBehavior)
}

func (f *MessageFilter) setFilter(tag uint32, sub filter, matchIfMissing bool) {
	mb := missingIsMismatch
	if matchIfMissing {
		mb = missingIsMatch
	}
	f.setFilterEx(tag, sub, mb)
}

func (f *MessageFilter) EqualBytes(tag uint32, eq []byte, matchIfMissing bool) {
	f.setFilter(tag, equalBytes{eq}, matchIfMissing)
}

func (f *MessageFilter) EqualString(tag uint32, eq string, matchIfMissing bool) {
	f.setFilter(tag, equalBytes{[]byte(eq)}, matchIfMissing)
}

func (f *MessageFilter) BytesIn(tag uint32, eq [][]byte, matchIfMissing bool) {
	f.setFilter(tag, bytesIn{eq}, matchIfMissing)
}

func (f *MessageFilter) StringIn(tag uint32, eq []string, matchIfMissing bool) {
	converted := make([][]byte, len(eq))
	for i, s := range eq {
		converted[i] = []byte(s)
	}
	f.setFilter(tag, bytesIn{converted}, matchIfMissing)
}

func (f *MessageFilter) EqualBool(tag uint32, eq bool, matchIfMissing bool) {
	var n uint64
	if eq {
		n = 1
	}
	f.setFilter(tag, equalUnsignedInt{n}, matchIfMissing)
}

// ExtractBytes changes the filter to call cb(v) if it encounters the given tag.
// The slice given to the callback is a subslice of the slice given to Match().
func (f *MessageFilter) ExtractBytes(tag uint32, cb func([]byte) error) {
	f.setFilter(tag, extractBytes{cb}, true)
}

func (f *MessageFilter) ExtractString(tag uint32, cb func(string) error) {
	f.setFilter(tag, extractString{cb}, true)
}

func (f *MessageFilter) ExtractBool(tag uint32, cb func(bool) error) {
	f.setFilter(tag, extractBool{cb}, true)
}

func (f *MessageFilter) TagExists(tag uint32) {
	f.setFilter(tag, tagExists{}, false)
}

func (f MessageFilter) Match(pb []byte) (bool, error) {
	err := f.match(wireLen, pb)
	switch err {
	case nil:
		return true, nil
	case errMismatch:
		return false, nil
	default:
		return false, err
	}
}

type filter interface {
	match(wireType wireType, pb []byte) error
}

func (f MessageFilter) match(_ wireType, pb []byte) error {
	remaining := len(f.filters)
	if remaining == 0 {
		return nil
	}
	var seen []bool
	if len(f.filters) < 16 {
		var array [16]bool
		seen = array[:]
	} else {
		seen = make([]bool, len(f.filters))
	}
	for len(pb) > 0 {
		n, sz := binary.Uvarint(pb)
		if sz <= 0 || n > math.MaxUint32 {
			return ErrCorrupted
		}
		pb = pb[sz:]
		wt := wireType(n & 7)
		field := uint32(n >> 3)
		var len int32
		switch wt {
		case wireVarint:
			for pb[len]&128 == 128 {
				len++
			}
			len++
		case wireI64:
			len = 8
		case wireLen:
			l, sz := binary.Uvarint(pb)
			if sz <= 0 || n > math.MaxInt32 {
				return ErrCorrupted
			}
			pb = pb[sz:]
			len = int32(l)
		case wireSgroup, wireEgroup:
			len = 0
		case wireI32:
			len = 4
		default:
			return ErrCorrupted
		}
		if idx, ok := f.tagLookup[field]; ok {
			if seen[idx] {
				return ErrLastWinsUnsupported
			}
			seen[idx] = true
			if err := f.filters[idx].match(wt, pb[:len]); err != nil {
				return err
			}
			remaining--
			if remaining == 0 {
				return nil
			}
		}
		pb = pb[len:]
	}
	for i, s := range seen {
		if !s {
			switch f.missingBehavior[i] {
			case missingIsMismatch:
				return errMismatch
			case missingIsMatch:
			case descendIfMissing:
				if err := f.filters[i].match(wireLen, nil); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type equalBytes struct {
	eq []byte
}

func (f equalBytes) match(wireType wireType, pb []byte) error {
	if !bytes.Equal(pb, f.eq) {
		return errMismatch
	}
	return nil
}

type bytesIn struct {
	eq [][]byte
}

func (f bytesIn) match(wireType wireType, pb []byte) error {
	for _, eq := range f.eq {
		if bytes.Equal(pb, eq) {
			return nil
		}
	}
	return errMismatch
}

type tagExists struct {
	eq []byte
}

func (f tagExists) match(wireType wireType, pb []byte) error {
	return nil
}

func decodeFloat32(wireType wireType, pb []byte) (float32, error) {
	if wireType != wireI32 {
		return 0, errors.New("EqualFloat32 filter encountered non float32 data")
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(pb)), nil
}

func decodeFloat64(wireType wireType, pb []byte) (float64, error) {
	if wireType != wireI64 {
		return 0, errors.New("EqualFloat64 filter encountered non float64 data")
	}
	return math.Float64frombits(binary.LittleEndian.Uint64(pb)), nil
}

func decodeUnsignedInt(wireType wireType, pb []byte) (uint64, error) {
	switch wireType {
	case wireVarint:
		n, _ := binary.Uvarint(pb)
		return n, nil
	case wireI32:
		return uint64(binary.LittleEndian.Uint32(pb)), nil
	case wireI64:
		return binary.LittleEndian.Uint64(pb), nil
	default:
		return 0, errors.New("numeric filter encountered non numeric data")
	}
}

func decodeSignedInt(wireType wireType, pb []byte) (int64, error) {
	switch wireType {
	case wireVarint:
		// Uses ZigZag encoding.
		n, _ := binary.Varint(pb)
		return n, nil
	case wireI32:
		return int64(int32(binary.LittleEndian.Uint32(pb))), nil
	case wireI64:
		return int64(binary.LittleEndian.Uint64(pb)), nil
	default:
		return 0, errors.New("numeric filter encountered non numeric data")
	}
}

func decodeInt32(wireType wireType, pb []byte) (int32, error) {
	switch wireType {
	case wireVarint:
		n, _ := binary.Uvarint(pb)
		return int32(uint32(n)), nil
	case wireI32:
		return int32(binary.LittleEndian.Uint32(pb)), nil
	case wireI64:
		return int32(binary.LittleEndian.Uint64(pb)), nil
	default:
		return 0, errors.New("numeric filter encountered non numeric data")
	}
}

func decodeInt64(wireType wireType, pb []byte) (int64, error) {
	switch wireType {
	case wireVarint:
		n, _ := binary.Uvarint(pb)
		return int64(n), nil
	case wireI32:
		return int64(int32(binary.LittleEndian.Uint32(pb))), nil
	case wireI64:
		return int64(binary.LittleEndian.Uint64(pb)), nil
	default:
		return 0, errors.New("numeric filter encountered non numeric data")
	}
}

type extractBytes struct {
	cb func([]byte) error
}

func (f extractBytes) match(wireType wireType, pb []byte) error {
	return f.cb(pb)
}

type extractString struct {
	cb func(string) error
}

func (f extractString) match(wireType wireType, pb []byte) error {
	return f.cb(string(pb))
}

type extractBool struct {
	cb func(bool) error
}

func (f extractBool) match(wireType wireType, pb []byte) error {
	if wireType != wireVarint {
		return errors.New("ExtractBool filter encountered non varint data")
	}
	n, _ := binary.Uvarint(pb)
	return f.cb(n != 0)
}
