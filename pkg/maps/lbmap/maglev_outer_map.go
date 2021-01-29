// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lbmap

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
)

// maglevOuterMap is the internal representation of a maglev outer map.
type maglevOuterMap struct {
	*ebpf.Map
	TableSize uint64
}

// MaglevOuterKey is the key of a maglev outer map.
type MaglevOuterKey struct {
	RevNatID uint16
}

// MaglevOuterVal is the value of a maglev outer map.
type MaglevOuterVal struct {
	FD uint32
}

// MaglevOuterMapName returns the name of an IPv4 or IPv6 maglev map, in the
// format cilium_lb{4, 6}_maglev_{table_size}
func MaglevOuterMapName(mapPrefix string, tableSize uint64) string {
	return fmt.Sprintf("%s_%d", mapPrefix, tableSize)
}

// MaglevOuter4MapName returns the name of the IPv4 maglev BPF map, in the
// format cilium_lb4_maglev_{table_size}
func MaglevOuter4MapName(tableSize uint64) string {
	return MaglevOuterMapName(MaglevOuter4MapPrefix, tableSize)
}

// MaglevOuter6MapName returns the name of the IPv6 maglev BPF map, in the
// format cilium_lb6_maglev_{table_size}
func MaglevOuter6MapName(tableSize uint64) string {
	return MaglevOuterMapName(MaglevOuter6MapPrefix, tableSize)
}

// NewMaglevOuterMap returns a new object representing a maglev outer map.
func NewMaglevOuterMap(name string, maxEntries int, tableSize uint64, innerMap *ebpf.MapSpec) (*maglevOuterMap, error) {
	m := ebpf.NewMap(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.HashOfMaps,
		KeySize:    uint32(unsafe.Sizeof(MaglevOuterKey{})),
		ValueSize:  uint32(unsafe.Sizeof(MaglevOuterVal{})),
		MaxEntries: uint32(maxEntries),
		InnerMap:   innerMap,
		Pinning:    ebpf.PinByName,
	})

	if err := m.OpenOrCreate(); err != nil {
		return nil, err
	}

	return &maglevOuterMap{
		Map:       m,
		TableSize: tableSize,
	}, nil
}

// MaglevOuterMapTableSize returns the maglev table size for a given maglev
// outer map (identified by its prefix).
// The table size value is extracted from the map name.
func MaglevOuterMapTableSize(mapPrefix string) (bool, uint64) {
	file, err := os.Open(bpf.MapPrefixPath())
	if err != nil {
		return false, 0
	}
	defer file.Close()

	list, err := file.Readdirnames(0)
	if err != nil {
		return false, 0
	}

	r := regexp.MustCompile(fmt.Sprintf("%s_(\\d+)", mapPrefix))
	for _, mapName := range list {
		res := r.FindStringSubmatch(mapName)
		if len(res) == 0 {
			continue
		}

		size, err := strconv.ParseUint(res[1], 10, 16)
		if err != nil {
			return false, 0
		}

		return true, size
	}

	return false, 0
}

// Lookup updates the value associated with a given key for a maglev outer map.
func (m *maglevOuterMap) Update(key *MaglevOuterKey, value *MaglevOuterVal) error {
	return m.Map.Update(key, value, 0)
}

// IterateCallback represents the signature of the callback function expected by
// the IterateWithCallback method, which in turn is used to iterate all the
// keys/values of a metrics map.
type MaglevOuterIterateCallback func(*MaglevOuterKey, *MaglevOuterVal)

// IterateWithCallback iterates through all the keys/values of a metrics map,
// passing each key/value pair to the cb callback
func (m maglevOuterMap) IterateWithCallback(cb MaglevOuterIterateCallback) error {
	return m.Map.IterateWithCallback(&MaglevOuterKey{}, &MaglevOuterVal{}, func(k, v interface{}) {
		key := k.(*MaglevOuterKey)
		value := v.(*MaglevOuterVal)

		cb(key, value)
	})
}

// ToNetwork converts a maglev outer map's key to network byte order.
func (k *MaglevOuterKey) ToNetwork() *MaglevOuterKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNatID = byteorder.HostToNetwork(n.RevNatID).(uint16)
	return &n
}
