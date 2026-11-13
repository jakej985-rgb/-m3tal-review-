package golang

import (
	"fmt"
	"go/token"
	"reflect"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/ssa"
)

// finish resolves call graphs and performs final deterministic
// ordering of per-function call targets.
func (c *converter) finish() {
	if c.callMode == CallGraphNone {
		// Still sort static callee lists for determinism.
	} else if c.callMode == CallGraphStatic {
		// Static callees were already attached during conversion.
	} else {
		c.applyCHA()
	}
	for _, p := range c.prog.Packages {
		for _, fn := range p.Functions {
			for _, call := range fn.Calls {
				sort.Slice(call.Callees, func(i, j int) bool {
					return call.Callees[i].ID < call.Callees[j].ID
				})
			}
		}
	}
}

// applyCHA runs class-hierarchy analysis over the SSA program and
// merges its edges into the model's call sites.
func (c *converter) applyCHA() {
	cg := cha.CallGraph(c.ssaProg)
	for _, node := range cg.Nodes {
		if node.Func == nil {
			continue
		}
		caller := c.fnMap[node.Func]
		_ = caller // caller membership already ensured by conversion
		for _, edge := range node.Out {
			site, ok := edge.Site.(ssa.CallInstruction)
			if !ok || site == nil {
				continue
			}
			call := c.callMap[site]
			if call == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}
			callee := c.function(edge.Callee.Func)
			if !hasCallee(call, callee) {
				call.Callees = append(call.Callees, callee)
			}
		}
	}
}

func hasCallee(call *semantic.Call, fn *semantic.Function) bool {
	for _, f := range call.Callees {
		if f == fn {
			return true
		}
	}
	return false
}

// callModel converts an SSA call instruction into a model Call and
// records it for later call-graph resolution.
func (c *converter) callModel(ci ssa.CallInstruction, site *semantic.Instruction) *semantic.Call {
	common := ci.Common()
	call := &semantic.Call{
		Site:   site,
		Target: c.callTarget(common),
	}
	switch ci.(type) {
	case *ssa.Go:
		call.Kind = semantic.CallGo
	case *ssa.Defer:
		call.Kind = semantic.CallDefer
	default:
		call.Kind = semantic.CallDirect
	}
	if fn := common.StaticCallee(); fn != nil {
		// Always materialize the callee so generic instances keep their
		// bodies; CallGraphNone just leaves the edge off the site.
		callee := c.function(fn)
		if c.callMode != CallGraphNone {
			call.Callees = []*semantic.Function{callee}
		}
	} else if _, builtin := common.Value.(*ssa.Builtin); builtin {
		// Builtins (panic, append, ...) are not modeled as functions.
	} else {
		call.Dynamic = true
	}
	c.callMap[ci] = call
	return call
}

// callTarget renders a human-readable callee description.
func (c *converter) callTarget(common *ssa.CallCommon) string {
	if fn := common.StaticCallee(); fn != nil {
		return fn.RelString(nil)
	}
	if _, builtin := common.Value.(*ssa.Builtin); builtin {
		return "builtin: " + common.Value.Name()
	}
	if common.IsInvoke() && common.Method != nil {
		recv := common.Value.Type()
		if recv != nil {
			return fmt.Sprintf("%s.%s", recv.String(), common.Method.Name())
		}
		return common.Method.Name()
	}
	if common.Value != nil && common.Value.Type() != nil {
		return fmt.Sprintf("%s: %s", common.Description(), common.Value.Type().String())
	}
	return common.Description()
}

// mapOp maps an SSA instruction to a neutral operation category.
func mapOp(instr ssa.Instruction) (semantic.Op, string) {
	switch v := instr.(type) {
	case *ssa.Alloc:
		return semantic.OpAlloc, ""
	case *ssa.UnOp:
		switch v.Op {
		case token.MUL:
			return semantic.OpLoad, ""
		case token.AND:
			return semantic.OpAddr, ""
		case token.ARROW:
			return semantic.OpRecv, ""
		default:
			return semantic.OpOther, "UnOp:" + v.Op.String()
		}
	case *ssa.Store:
		return semantic.OpStore, ""
	case *ssa.Field, *ssa.FieldAddr:
		return semantic.OpField, ""
	case *ssa.Index, *ssa.IndexAddr, *ssa.Lookup:
		return semantic.OpIndex, ""
	case *ssa.Slice:
		return semantic.OpSlice, ""
	case *ssa.Call:
		return semantic.OpCall, ""
	case *ssa.Go:
		return semantic.OpGo, ""
	case *ssa.Defer:
		return semantic.OpDefer, ""
	case *ssa.Return:
		return semantic.OpReturn, ""
	case *ssa.If:
		return semantic.OpBranch, ""
	case *ssa.Jump:
		return semantic.OpJump, ""
	case *ssa.Phi:
		return semantic.OpPhi, ""
	case *ssa.Convert, *ssa.ChangeType, *ssa.ChangeInterface, *ssa.MakeInterface:
		return semantic.OpConvert, ""
	case *ssa.TypeAssert:
		return semantic.OpTypeAssert, ""
	case *ssa.Send:
		return semantic.OpSend, ""
	case *ssa.MakeSlice, *ssa.MakeMap, *ssa.MakeChan:
		return semantic.OpAlloc, ""
	default:
		return semantic.OpOther, instrName(instr)
	}
}

// instrName returns a short frontend-specific name for an instruction,
// e.g. "ssa.MapUpdate".
func instrName(instr ssa.Instruction) string {
	t := reflect.TypeOf(instr)
	if t == nil {
		return "unknown"
	}
	return strings.TrimPrefix(t.String(), "*ssa.")
}
