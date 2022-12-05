// Copyright 2014 The go-ethereum Authors
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

package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

// Config are the configuration options for the Interpreter
type Config struct {
	Debug                   bool      // Enables debugging
	Tracer                  EVMLogger // Opcode logger
	NoBaseFee               bool      // Forces the EIP-1559 baseFee to 0 (needed for 0 price calls)
	EnablePreimageRecording bool      // Enables recording of SHA3/keccak preimages

	JumpTable *JumpTable // EVM instruction table, automatically populated if unset

	ExtraEips []int // Additional EIPS that are to be enabled
}

// ScopeContext contains the things that are per-call, such as stack and memory,
// but not transients like pc and gas
type ScopeContext struct {
	Memory   *Memory
	Stack    *Stack
	Contract *Contract
}

// EVMInterpreter represents an EVM interpreter
type EVMInterpreter struct {
	evm *EVM
	cfg Config

	hasher    crypto.KeccakState // Keccak256 hasher instance shared across opcodes
	hasherBuf common.Hash        // Keccak256 hasher result array shared aross opcodes

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return data for subsequent reuse
}

// NewEVMInterpreter returns a new instance of the Interpreter.
func NewEVMInterpreter(evm *EVM, cfg Config) *EVMInterpreter {
	// If jump table was not initialised we set the default one.
	if cfg.JumpTable == nil {
		switch {
		case evm.chainRules.IsMerge:
			cfg.JumpTable = &mergeInstructionSet
		case evm.chainRules.IsLondon:
			cfg.JumpTable = &londonInstructionSet
		case evm.chainRules.IsBerlin:
			cfg.JumpTable = &berlinInstructionSet
		case evm.chainRules.IsIstanbul:
			cfg.JumpTable = &istanbulInstructionSet
		case evm.chainRules.IsConstantinople:
			cfg.JumpTable = &constantinopleInstructionSet
		case evm.chainRules.IsByzantium:
			cfg.JumpTable = &byzantiumInstructionSet
		case evm.chainRules.IsEIP158:
			cfg.JumpTable = &spuriousDragonInstructionSet
		case evm.chainRules.IsEIP150:
			cfg.JumpTable = &tangerineWhistleInstructionSet
		case evm.chainRules.IsHomestead:
			cfg.JumpTable = &homesteadInstructionSet
		default:
			cfg.JumpTable = &frontierInstructionSet
		}
		var extraEips []int
		if len(cfg.ExtraEips) > 0 {
			// Deep-copy jumptable to prevent modification of opcodes in other tables
			cfg.JumpTable = copyJumpTable(cfg.JumpTable)
		}
		for _, eip := range cfg.ExtraEips {
			if err := EnableEIP(eip, cfg.JumpTable); err != nil {
				// Disable it, so caller can check if it's activated or not
				log.Error("EIP activation failed", "eip", eip, "error", err)
			} else {
				extraEips = append(extraEips, eip)
			}
		}
		cfg.ExtraEips = extraEips
	}

	return &EVMInterpreter{
		evm: evm,
		cfg: cfg,
	}
}

// Run loops and evaluates the contract's code with the given input data and returns 使用给定的输入数据循环并评估合约代码并返回
// the return byte-slice and an error if one occurred. 返回字节切片和错误（如果发生）
//
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation except for
// ErrExecutionReverted which means revert-and-keep-gas-left. 重要的是要注意，解释器返回的任何错误都应被视为 revert-and-consume-all-gas 操作，但 ErrExecutionReverted 除外，它表示 revert-and-keep-gas-left
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	// Increment the call depth which is restricted to 1024 增加限制为 1024 的调用深度
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Make sure the readOnly is only set if we aren't in readOnly yet. 确保仅在我们尚未处于只读状态时才设置只读。
	// This also makes sure that the readOnly flag isn't removed for child calls. 这也确保不会为子调用删除 readOnly 标志。
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}

	// Reset the previous call's return data. It's unimportant to preserve the old buffer
	// as every returning call will return new data anyway. 重置先前调用的返回数据。 保留旧缓冲区并不重要，因为每次返回的调用都会返回新数据。
	in.returnData = nil

	// Don't bother with the execution if there's no code. 如果没有代码，退出执行。
	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		op          OpCode        // current opcode
		mem         = NewMemory() // bound memory
		stack       = newstack()  // local stack
		callContext = &ScopeContext{
			Memory:   mem,
			Stack:    stack,
			Contract: contract,
		}
		// For optimisation reason we're using uint64 as the program counter. 出于优化原因，我们使用 uint64 作为程序计数器。
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible. 理论上可以超过 2^64。 YP 将 PC 定义为 uint256。 实际上不太可行。
		pc   = uint64(0) // program counter 程序计数器
		cost uint64
		// copies used by tracer
		pcCopy  uint64 // needed for the deferred EVMLogger
		gasCopy uint64 // for EVMLogger to log gas remaining before execution
		logged  bool   // deferred EVMLogger should ignore already logged steps
		res     []byte // result of the opcode execution function
	)
	// Don't move this deferred function, it's placed before the capturestate-deferred method,
	// so that it get's executed _after_: the capturestate needs the stacks before
	// they are returned to the pools 不要移动这个延迟函数，它被放置在 capturestate-deferred 方法之前，以便它在 _after_ 被执行：capturestate 在它们返回到池之前需要堆栈
	defer func() {
		returnStack(stack)
	}()
	contract.Input = input

	if in.cfg.Debug {
		defer func() {
			if err != nil {
				if !logged {
					in.cfg.Tracer.CaptureState(pcCopy, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
				} else {
					in.cfg.Tracer.CaptureFault(pcCopy, op, gasCopy, cost, callContext, in.evm.depth, err)
				}
			}
		}()
	}
	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context. 解释器主运行循环（上下文）。 该循环一直运行，直到执行了显式的 STOP、RETURN 或 SELFDESTRUCT，在执行其中一个操作期间发生错误，或者直到完成标志被父上下文设置。
	for {
		if in.cfg.Debug {
			// Capture pre-execution values for tracing. 捕获执行前的值以进行跟踪。
			logged, pcCopy, gasCopy = false, pc, contract.Gas
		}
		// Get the operation from the jump table and validate the stack to ensure there are
		// enough stack items available to perform the operation. 从跳转表中获取操作并验证堆栈以确保有足够的堆栈项可用于执行操作。
		op = contract.GetOp(pc)
		operation := in.cfg.JumpTable[op]
		/*operation SHA3: {
		      execute:       opSha3,
		      gasCost:       gasSha3,
		      validateStack: makeStackFunc(2, 1),
		      memorySize:    memorySha3,
		      valid:         true,
		  }
			execute 表示指令对应的执行方法
			gasCost 表示执行这个指令需要消耗的gas
			validateStack 计算是不是解析器栈溢出
			memorySize 用于计算operation的占用内存大小
		*/
		cost = operation.constantGas // For tracing
		// Validate stack 验证堆栈
		if sLen := stack.len(); sLen < operation.minStack {
			return nil, &ErrStackUnderflow{stackLen: sLen, required: operation.minStack}
		} else if sLen > operation.maxStack {
			return nil, &ErrStackOverflow{stackLen: sLen, limit: operation.maxStack}
		}
		if !contract.UseGas(cost) {
			return nil, ErrOutOfGas
		}
		if operation.dynamicGas != nil {
			// All ops with a dynamic memory usage also has a dynamic gas cost. 所有使用动态内存的操作也有动态的 gas 成本。
			var memorySize uint64
			// calculate the new memory size and expand the memory to fit 计算新的内存大小并扩展内存以适应
			// the operation
			// Memory check needs to be done prior to evaluating the dynamic gas portion,
			// to detect calculation overflows 在评估动态气体部分之前，需要进行内存检查，以检测计算溢出
			if operation.memorySize != nil {
				memSize, overflow := operation.memorySize(stack)
				if overflow {
					return nil, ErrGasUintOverflow
				}
				// memory is expanded in words of 32 bytes. Gas
				// is also calculated in words. 内存以 32 字节的字扩展。 gas也是用文字来计算的。
				if memorySize, overflow = math.SafeMul(toWordSize(memSize), 32); overflow {
					return nil, ErrGasUintOverflow
				}
			}
			// Consume the gas and return an error if not enough gas is available. 如果没有足够的气体可用，消耗气体并返回错误。
			// cost is explicitly set so that the capture state defer method can get the proper cost 显式设置成本，以便捕获状态延迟方法可以获得适当的成本
			var dynamicCost uint64
			dynamicCost, err = operation.dynamicGas(in.evm, contract, stack, mem, memorySize)
			cost += dynamicCost // for tracing 用于追踪
			if err != nil || !contract.UseGas(dynamicCost) {
				return nil, ErrOutOfGas
			}
			// Do tracing before memory expansion 在内存扩展之前进行跟踪
			if in.cfg.Debug {
				in.cfg.Tracer.CaptureState(pc, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
				logged = true
			}
			if memorySize > 0 {
				mem.Resize(memorySize)
			}
		} else if in.cfg.Debug {
			in.cfg.Tracer.CaptureState(pc, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
			logged = true
		}
		// execute the operation 执行操作
		res, err = operation.execute(&pc, in, callContext)
		if err != nil {
			break
		}
		pc++
	}

	if err == errStopToken {
		err = nil // clear stop token error
	}

	return res, err
}
