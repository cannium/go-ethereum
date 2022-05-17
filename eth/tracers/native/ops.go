// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package native

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
)

// FIXME: call stack hierarchy has not been properly handled

func init() {
	register("opsTracer", newOpsTracer)
}

const (
	LabelTransfer         = "Transfer"
	LabelInternalTransfer = "Internal-Transfer"
)

type opsCallFrame struct {
	Type    string         `json:"type"`
	Label   string         `json:"label"`
	From    string         `json:"from"`
	To      string         `json:"to,omitempty"`
	Value   string         `json:"value,omitempty"`
	GasIn   string         `json:"gasIn"`
	GasCost string         `json:"gasUsed"`
	Input   string         `json:"input"`
	Output  string         `json:"output,omitempty"`
	Error   string         `json:"error,omitempty"`
	Calls   []opsCallFrame `json:"calls,omitempty"`
}

type opsTracer struct {
	env       *vm.EVM
	callstack []opsCallFrame
	interrupt uint32 // Atomic flag to signal execution interruption
	reason    error  // Textual reason for the interruption
}

// newOpsTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func newOpsTracer() tracers.Tracer {
	// First callframe contains tx context info
	// and is populated on start and end.
	return &opsTracer{callstack: make([]opsCallFrame, 1)}
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *opsTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	fmt.Println("CaptureStart", env, from, to, create, input, gas, value)
	t.env = env
	t.callstack[0] = opsCallFrame{
		Type:  "CALL",
		From:  addrToHex(from),
		To:    addrToHex(to),
		Input: bytesToHex(input),
		GasIn: uintToHex(gas),
		Value: bigToHex(value),
	}
	if create {
		t.callstack[0].Type = "CREATE"
	}
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *opsTracer) CaptureEnd(output []byte, gasUsed uint64, _ time.Duration, err error) {
	fmt.Println("CaptureEnd", output, gasUsed, err)
	t.callstack[0].GasCost = uintToHex(gasUsed)
	if err != nil {
		t.callstack[0].Error = err.Error()
		if err.Error() == "execution reverted" && len(output) > 0 {
			t.callstack[0].Output = bytesToHex(output)
		}
	} else {
		t.callstack[0].Output = bytesToHex(output)
	}
}

// Note the result has no "0x" prefix
func getLogValueHex(scope *vm.ScopeContext) string {
	offset := scope.Stack.Back(0).Uint64()
	length := scope.Stack.Back(1).Uint64()
	return hex.EncodeToString(scope.Memory.Data()[offset : offset+length])
}

// code modified from `4byte.go`
func (t *opsTracer) isPrecompiled(addr common.Address) bool {
	rules := t.env.ChainConfig().Rules(t.env.Context.BlockNumber,
		t.env.Context.Random != nil)
	activePrecompiles := vm.ActivePrecompiles(rules)
	for _, p := range activePrecompiles {
		if p == addr {
			return true
		}
	}
	return false
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *opsTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if err != nil {
		t.reason = err
		return
	}
	if op == vm.LOG0 || op == vm.LOG1 || op == vm.LOG2 || op == vm.LOG3 || op == vm.LOG4 {
		var topic0, topic1, topic2, topic3, logInput string
		switch op {
		case vm.LOG1:
			topic0 = scope.Stack.Back(2).String()[2:] // remove "0x" prefix
			logInput = topic0
		case vm.LOG2:
			topic0 = scope.Stack.Back(2).String()[2:] // remove "0x" prefix
			topic1 = scope.Stack.Back(3).String()[2:] // remove "0x" prefix
			logInput = topic0 + topic1
		case vm.LOG3:
			topic0 = scope.Stack.Back(2).String()[2:] // remove "0x" prefix
			topic1 = scope.Stack.Back(3).String()[2:] // remove "0x" prefix
			topic2 = scope.Stack.Back(4).String()[2:] // remove "0x" prefix
			logInput = topic0 + topic1 + topic2
		case vm.LOG4:
			topic0 = scope.Stack.Back(2).String()[2:] // remove "0x" prefix
			topic1 = scope.Stack.Back(3).String()[2:] // remove "0x" prefix
			topic2 = scope.Stack.Back(4).String()[2:] // remove "0x" prefix
			topic3 = scope.Stack.Back(5).String()[2:] // remove "0x" prefix
			logInput = topic0 + topic1 + topic2 + topic3
		}
		var label string
		// FIXME: add docs about the magic number
		if op != vm.LOG0 && topic0 == "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" {
			label = LabelTransfer
		}
		frame := opsCallFrame{
			Type:    op.String(),
			Label:   label,
			From:    scope.Contract.Address().String(),
			Input:   logInput,
			Value:   getLogValueHex(scope),
			GasIn:   uintToHex(gas),
			GasCost: uintToHex(cost),
		}
		t.callstack = append(t.callstack, frame)
		return
	}

	switch op {
	case vm.CREATE, vm.CREATE2:
		value := scope.Stack.Back(0)
		offset := scope.Stack.Back(1).Uint64()
		length := scope.Stack.Back(2).Uint64()
		frame := opsCallFrame{
			Type:    op.String(),
			From:    scope.Contract.Address().String(),
			Input:   hex.EncodeToString(scope.Memory.Data()[offset : offset+length]),
			GasIn:   uintToHex(gas),
			GasCost: uintToHex(cost),
			Value:   value.String(),
		}
		if !value.IsZero() {
			frame.Label = LabelInternalTransfer
		}
		t.callstack = append(t.callstack, frame)
		return
	case vm.SELFDESTRUCT:
		value := t.env.StateDB.GetBalance(scope.Contract.Address())
		frame := opsCallFrame{
			Type:    op.String(),
			From:    scope.Contract.Address().String(),
			To:      scope.Stack.Back(0).String(),
			GasIn:   uintToHex(gas),
			GasCost: uintToHex(cost),
			Value:   value.String(),
		}
		if value.Uint64() != 0 {
			frame.Label = LabelInternalTransfer
		}
		t.callstack = append(t.callstack, frame)
		return
	case vm.CALL, vm.CALLCODE:
		var to common.Address = scope.Stack.Back(1).Bytes20()
		if t.isPrecompiled(to) {
			return
		}
		argOffset := scope.Stack.Back(3).Uint64()
		argLength := scope.Stack.Back(4).Uint64()
		value := scope.Stack.Back(2)
		frame := opsCallFrame{
			Type:    op.String(),
			From:    scope.Contract.Address().String(),
			To:      to.String(),
			Value:   value.String(),
			Input:   hex.EncodeToString(scope.Memory.Data()[argOffset : argOffset+argLength]),
			GasIn:   uintToHex(gas),
			GasCost: uintToHex(cost),
		}
		if value.IsZero() {
			frame.Label = LabelInternalTransfer
		}
		t.callstack = append(t.callstack, frame)
		return
	case vm.DELEGATECALL, vm.STATICCALL:
		var to common.Address = scope.Stack.Back(1).Bytes20()
		if t.isPrecompiled(to) {
			return
		}
		argOffset := scope.Stack.Back(2).Uint64()
		argLength := scope.Stack.Back(3).Uint64()
		frame := opsCallFrame{
			Type:    op.String(),
			From:    scope.Contract.Address().String(),
			To:      to.String(),
			Input:   hex.EncodeToString(scope.Memory.Data()[argOffset : argOffset+argLength]),
			GasIn:   uintToHex(gas),
			GasCost: uintToHex(cost),
		}
		t.callstack = append(t.callstack, frame)
		return
	}
}

// CaptureFault implements the EVMLogger interface to trace an execution fault.
func (t *opsTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, _ *vm.ScopeContext, depth int, err error) {
	fmt.Println("CaptureFault", pc, op, gas, cost, depth, err)
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *opsTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	fmt.Println("CaptureEnter", typ, from, to, input, gas, value)
	// Skip if tracing was interrupted
	if atomic.LoadUint32(&t.interrupt) > 0 {
		t.env.Cancel()
		return
	}

	call := opsCallFrame{
		Type:  typ.String(),
		From:  addrToHex(from),
		To:    addrToHex(to),
		Input: bytesToHex(input),
		GasIn: uintToHex(gas),
		Value: bigToHex(value),
	}
	t.callstack = append(t.callstack, call)
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *opsTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	fmt.Println("CaptureExit", output, gasUsed, err)
	size := len(t.callstack)
	if size <= 1 {
		return
	}
	// pop call
	call := t.callstack[size-1]
	t.callstack = t.callstack[:size-1]
	size -= 1

	call.GasCost = uintToHex(gasUsed)
	if err == nil {
		call.Output = bytesToHex(output)
	} else {
		call.Error = err.Error()
		if call.Type == "CREATE" || call.Type == "CREATE2" {
			call.To = ""
		}
	}
	t.callstack[size-1].Calls = append(t.callstack[size-1].Calls, call)
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *opsTracer) GetResult() (json.RawMessage, error) {
	if len(t.callstack) != 1 {
		return nil, errors.New("incorrect number of top-level calls")
	}
	res, err := json.Marshal(t.callstack[0])
	if err != nil {
		return nil, err
	}
	return json.RawMessage(res), t.reason
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *opsTracer) Stop(err error) {
	t.reason = err
	atomic.StoreUint32(&t.interrupt, 1)
}
