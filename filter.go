// Package protolaser allows working with protocol buffer wire format data.
// It allows matching on specific fields without decoding the entire message.
package protolaser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/dennwc/varint"
	"google.golang.org/protobuf/encoding/protowire"
)

var (
	errMismatch            = errors.New("mismatch")
	ErrCorrupted           = errors.New("protobuf wire data is invalid")
	ErrLastWinsUnsupported = errors.New("the protobuf contained multiple values for a field but this is not supported by protolaser")
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
	err := f.match(protowire.BytesType, pb)
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
	match(wireType protowire.Type, pb []byte) error
}

func (f MessageFilter) match(_ protowire.Type, pb []byte) error {
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
		field, wireTypeByte, sz := varint.ProtoTag(pb)
		if sz == 0 || field > math.MaxUint32 {
			return ErrCorrupted
		}
		pb = pb[sz:]
		wt := protowire.Type(wireTypeByte)
		var len int32
		switch wt {
		case protowire.VarintType:
			for pb[len]&128 == 128 {
				len++
			}
			len++
		case protowire.Fixed64Type:
			len = 8
		case protowire.BytesType:
			l, sz := varint.Uvarint(pb)
			if sz <= 0 || l > math.MaxInt32 {
				return ErrCorrupted
			}
			pb = pb[sz:]
			len = int32(l)
		case protowire.StartGroupType, protowire.EndGroupType:
			len = 0
		case protowire.Fixed32Type:
			len = 4
		default:
			return ErrCorrupted
		}
		if idx, ok := f.tagLookup[uint32(field)]; ok {
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
				if err := f.filters[i].match(protowire.BytesType, nil); err != nil {
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

func (f equalBytes) match(wireType protowire.Type, pb []byte) error {
	if !bytes.Equal(pb, f.eq) {
		return errMismatch
	}
	return nil
}

type bytesIn struct {
	eq [][]byte
}

func (f bytesIn) match(wireType protowire.Type, pb []byte) error {
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

func (f tagExists) match(wireType protowire.Type, pb []byte) error {
	return nil
}

func decodeFloat32(wireType protowire.Type, pb []byte) (float32, error) {
	if wireType != protowire.Fixed32Type {
		return 0, errors.New("EqualFloat32 filter encountered non float32 data")
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(pb)), nil
}

func decodeFloat64(wireType protowire.Type, pb []byte) (float64, error) {
	if wireType != protowire.Fixed64Type {
		return 0, errors.New("EqualFloat64 filter encountered non float64 data")
	}
	return math.Float64frombits(binary.LittleEndian.Uint64(pb)), nil
}

func decodeUnsignedInt(wireType protowire.Type, pb []byte) (uint64, error) {
	switch wireType {
	case protowire.VarintType:
		n, _ := varint.Uvarint(pb)
		return n, nil
	case protowire.Fixed32Type:
		return uint64(binary.LittleEndian.Uint32(pb)), nil
	case protowire.Fixed64Type:
		return binary.LittleEndian.Uint64(pb), nil
	default:
		return 0, errors.New("numeric filter encountered non numeric data")
	}
}

func decodeSignedInt(wireType protowire.Type, pb []byte) (int64, error) {
	switch wireType {
	case protowire.VarintType:
		// Uses ZigZag encoding.
		n, _ := binary.Varint(pb)
		return n, nil
	case protowire.Fixed32Type:
		return int64(int32(binary.LittleEndian.Uint32(pb))), nil
	case protowire.Fixed64Type:
		return int64(binary.LittleEndian.Uint64(pb)), nil
	default:
		return 0, errors.New("numeric filter encountered non numeric data")
	}
}

func decodeInt32(wireType protowire.Type, pb []byte) (int32, error) {
	switch wireType {
	case protowire.VarintType:
		n, _ := varint.Uvarint(pb)
		return int32(uint32(n)), nil
	case protowire.Fixed32Type:
		return int32(binary.LittleEndian.Uint32(pb)), nil
	case protowire.Fixed64Type:
		return int32(binary.LittleEndian.Uint64(pb)), nil
	default:
		return 0, errors.New("numeric filter encountered non numeric data")
	}
}

func decodeInt64(wireType protowire.Type, pb []byte) (int64, error) {
	switch wireType {
	case protowire.VarintType:
		n, _ := varint.Uvarint(pb)
		return int64(n), nil
	case protowire.Fixed32Type:
		return int64(int32(binary.LittleEndian.Uint32(pb))), nil
	case protowire.Fixed64Type:
		return int64(binary.LittleEndian.Uint64(pb)), nil
	default:
		return 0, errors.New("numeric filter encountered non numeric data")
	}
}

type extractBytes struct {
	cb func([]byte) error
}

func (f extractBytes) match(wireType protowire.Type, pb []byte) error {
	return f.cb(pb)
}

type extractString struct {
	cb func(string) error
}

func (f extractString) match(wireType protowire.Type, pb []byte) error {
	return f.cb(string(pb))
}

type extractBool struct {
	cb func(bool) error
}

func (f extractBool) match(wireType protowire.Type, pb []byte) error {
	if wireType != protowire.VarintType {
		return errors.New("ExtractBool filter encountered non varint data")
	}
	n, _ := varint.Uvarint(pb)
	return f.cb(n != 0)
}
