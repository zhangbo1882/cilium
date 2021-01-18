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

package cmd

import (
	"fmt"
	"unsafe"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/lbmap"
)

// bpfMaglevListCmd represents the bpf lb maglev list command
var bpfMaglevListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List Maglev lookup tables",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb maglev list")

		lookupTables := map[string][]string{}
		dumpMaglevTables(lookupTables)

		if command.OutputJSON() {
			if err := command.PrintOutput(lookupTables); err != nil {
				Fatalf("Unable to generate JSON output: %s", err)
			}
			return
		}

		TablePrinter("SVC ID", "LOOKUP TABLE", lookupTables)
	},
}

func parseMaglevEntry(key bpf.MapKey, value bpf.MapValue, tables map[string][]string) {
	k := key.(*lbmap.MaglevOuterKey)
	v := value.(*lbmap.MaglevOuterVal)

	table := make([]uint16, lbmap.MaglevTableSize)
	zero := uint32(0)
	fd, err := bpf.MapFdFromID(int(v.FD))
	if err != nil {
		Fatalf("Unable to get map fd by id %d: %s", v.FD, err)
	}
	if err := bpf.LookupElement(int(fd), unsafe.Pointer(&zero), unsafe.Pointer(&table[0])); err != nil {
		Fatalf("Unable to lookup element in map by fd %d: %s", fd, err)
	}
	tables[k.ToNetwork().String()] = []string{fmt.Sprintf("%v", table)}
}

func dumpMaglevTables(tables map[string][]string) {
	// Maglev maps require map preallocation to be enabled (otherwise we
	// would get a flag mismatch with the existing map which would led to
	// the recreation of the map)
	if bpf.GetMapPreAllocationSetting() == 1 {
		bpf.EnableMapPreAllocation()
		defer bpf.DisableMapPreAllocation()
	}

	if err := lbmap.MaybeInitMaglevMapsByProbingTableSize(); err != nil {
		Fatalf("Cannot initialize maglev maps: %s", err)
	}

	parse := func(key bpf.MapKey, value bpf.MapValue) {
		parseMaglevEntry(key, value, tables)
	}

	for name, m := range lbmap.GetOpenMaglevMaps() {
		if err := m.DumpWithCallback(parse); err != nil {
			Fatalf("Unable to dump %s: %v", name, err)
		}
	}

}

func init() {
	bpfMaglevCmd.AddCommand(bpfMaglevListCmd)
	command.AddJSONOutput(bpfMaglevListCmd)
}
