// Copyright 2020 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// Both inner maps are not being pinned into BPF fs.
	MaglevInner4MapName = "cilium_lb4_maglev_inner"
	MaglevInner6MapName = "cilium_lb6_maglev_inner"

	// Both outer maps are pinned though given we need to attach
	// inner maps into them.
	MaglevOuter4MapPrefix = "cilium_lb4_maglev"
	MaglevOuter6MapPrefix = "cilium_lb6_maglev"
)

var (
	MaglevOuter4Map     *bpf.Map
	MaglevOuter6Map     *bpf.Map
	MaglevTableSize     uint64
	maglevRecreatedIPv4 bool
	maglevRecreatedIPv6 bool
)

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

// InitMaglevMaps inits the ipv4 and/or ipv6 maglev outer and inner maps.
func InitMaglevMaps(ipv4, ipv6 bool, tableSize uint64) error {
	var err error

	dummyInnerMap := newInnerMaglevMap("cilium_lb_maglev_dummy", tableSize)
	if err := dummyInnerMap.CreateUnpinned(); err != nil {
		return err
	}
	defer dummyInnerMap.Close()

	if maglevRecreatedIPv4, err = deleteMapIfMNotMatch(MaglevOuter4MapPrefix, tableSize); err != nil {
		return err
	}
	if maglevRecreatedIPv6, err = deleteMapIfMNotMatch(MaglevOuter6MapPrefix, tableSize); err != nil {
		return err
	}

	if ipv4 {
		MaglevOuter4Map = newOuterMaglevMap(MaglevOuter4MapPrefix, tableSize, dummyInnerMap)
		if _, err := MaglevOuter4Map.OpenOrCreate(); err != nil {
			return err
		}
	}
	if ipv6 {
		MaglevOuter6Map = newOuterMaglevMap(MaglevOuter6MapPrefix, tableSize, dummyInnerMap)
		if _, err := MaglevOuter6Map.OpenOrCreate(); err != nil {
			return err
		}
	}

	MaglevTableSize = tableSize

	return nil
}

// MaglevOuterMapTableSize returns the maglev table size for a given maglev
// outer map (identified by its prefix). The table size value is extracted from
// the map name.
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

// MayveInitMaglevMapsByProbingTableSize tries to initialize all maglev eBPF
// maps.
func MaybeInitMaglevMapsByProbingTableSize() error {
	var detectedTableSize uint64

	map4Found, maglev4TableSize := MaglevOuterMapTableSize(MaglevOuter4MapPrefix)
	map6Found, maglev6TableSize := MaglevOuterMapTableSize(MaglevOuter6MapPrefix)

	switch {
	case !map4Found && !map6Found:
		return nil
	case map4Found && map6Found && maglev4TableSize != maglev6TableSize:
		// Just being extra defensive here. This case should never
		// happen as both maps are created at the same time after
		// deleting eventual old maps with a different M parameter
		return fmt.Errorf("v4 and v6 maps have different table sizes")
	case map4Found:
		detectedTableSize = maglev4TableSize
	case map6Found:
		detectedTableSize = maglev6TableSize
	}

	return InitMaglevMaps(map4Found, map6Found, detectedTableSize)
}

// GetOpenMaglevMaps returns a map with all the outer maglev eBPF maps which are
// opened. These eBPF maps are indexed by their name.
func GetOpenMaglevMaps() map[string]*bpf.Map {
	maps := map[string]*bpf.Map{}
	switch {
	case MaglevOuter4Map != nil:
		maps[MaglevOuter4MapName(MaglevTableSize)] = MaglevOuter4Map
	case MaglevOuter6Map != nil:
		maps[MaglevOuter6MapName(MaglevTableSize)] = MaglevOuter6Map
	}

	return maps
}

// deleteMapIfMNotMatch removes the outer maglev maps if the M param
// (MaglevTableSize) has changed. This is to avoid the verifier error when
// loading BPF programs which access the maps.
func deleteMapIfMNotMatch(mapPrefix string, tableSize uint64) (bool, error) {
	found, previousTableSize := MaglevOuterMapTableSize(mapPrefix)
	if !found || tableSize == previousTableSize {
		return false, nil
	}

	prevMapName := MaglevOuterMapName(mapPrefix, previousTableSize)

	m, err := bpf.OpenMap(prevMapName)
	if err != nil {
		return false, err
	}

	log.WithField(logfields.BPFMapName, prevMapName).Info("Deleting Maglev outer map due to different M")
	if err := m.Unpin(); err != nil {
		return false, err
	}

	return true, nil
}

func newInnerMaglevMap(name string, tableSize uint64) *bpf.Map {
	return bpf.NewMapWithOpts(
		name,
		bpf.MapTypeArray,
		&MaglevInnerKey{}, int(unsafe.Sizeof(MaglevInnerKey{})),
		&MaglevInnerVal{}, int(unsafe.Sizeof(uint16(0)))*int(tableSize),
		1, 0, 0,
		bpf.ConvertKeyValue,
		&bpf.NewMapOpts{},
	)
}

func newOuterMaglevMap(mapPrefix string, tableSize uint64, innerMap *bpf.Map) *bpf.Map {
	return bpf.NewMap(
		MaglevOuterMapName(mapPrefix, tableSize),
		bpf.MapTypeHashOfMaps,
		&MaglevOuterKey{}, int(unsafe.Sizeof(MaglevOuterKey{})),
		&MaglevOuterVal{}, int(unsafe.Sizeof(MaglevOuterVal{})),
		MaxEntries,
		0, uint32(innerMap.GetFd()),
		bpf.ConvertKeyValue,
	)
}

func updateMaglevTable(ipv6 bool, revNATID uint16, backendIDs []uint16) error {
	outerMap := MaglevOuter4Map
	innerMapName := MaglevInner4MapName
	if ipv6 {
		outerMap = MaglevOuter6Map
		innerMapName = MaglevInner6MapName
	}

	innerMap := newInnerMaglevMap(innerMapName, MaglevTableSize)
	if err := innerMap.CreateUnpinned(); err != nil {
		return err
	}
	defer innerMap.Close()

	innerKey := &MaglevInnerKey{Zero: 0}
	innerVal := &MaglevInnerVal{BackendIDs: backendIDs}
	if err := innerMap.Update(innerKey, innerVal); err != nil {
		return err
	}

	outerKey := (&MaglevOuterKey{RevNatID: revNATID}).ToNetwork()
	outerVal := &MaglevOuterVal{FD: uint32(innerMap.GetFd())}
	if err := outerMap.Update(outerKey, outerVal); err != nil {
		return err
	}

	return nil
}

func deleteMaglevTable(ipv6 bool, revNATID uint16) error {
	outerMap := MaglevOuter4Map
	if ipv6 {
		outerMap = MaglevOuter6Map
	}

	outerKey := (&MaglevOuterKey{RevNatID: revNATID}).ToNetwork()
	if err := outerMap.Delete(outerKey); err != nil {
		return err
	}

	return nil
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type MaglevInnerKey struct{ Zero uint32 }

func (k *MaglevInnerKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *MaglevInnerKey) NewValue() bpf.MapValue    { return &MaglevInnerVal{} }
func (k *MaglevInnerKey) String() string            { return fmt.Sprintf("%d", k.Zero) }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type MaglevInnerVal struct {
	BackendIDs []uint16
}

func (v *MaglevInnerVal) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v.BackendIDs[0]) }
func (v *MaglevInnerVal) String() string              { return fmt.Sprintf("%v", v.BackendIDs) }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type MaglevOuterKey struct{ RevNatID uint16 }

func (k *MaglevOuterKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *MaglevOuterKey) NewValue() bpf.MapValue    { return &MaglevOuterVal{} }
func (k *MaglevOuterKey) String() string            { return fmt.Sprintf("%d", k.RevNatID) }
func (k *MaglevOuterKey) ToNetwork() *MaglevOuterKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNatID = byteorder.HostToNetwork(n.RevNatID).(uint16)
	return &n
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type MaglevOuterVal struct{ FD uint32 }

func (v *MaglevOuterVal) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *MaglevOuterVal) String() string              { return fmt.Sprintf("%d", v.FD) }
