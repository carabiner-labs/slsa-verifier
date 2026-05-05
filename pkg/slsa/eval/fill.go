// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// FillNilMessages walks a protobuf message tree and ensures every
// singular message-typed field is allocated (zero-valued if the
// parsed payload omitted it). This makes CEL expressions like
//
//	predicate.runDetails.builder.id
//
// safe to evaluate when intermediate fields are absent: the chain
// resolves to the zero value of the leaf field instead of erroring on
// a nil intermediate message.
//
// Lists and maps of messages are walked so their entries are filled
// recursively. Oneof cases are not auto-allocated (a oneof selects at
// most one variant — automatically materialising one is wrong).
// Well-known google.protobuf.* types (Struct, Value, ListValue, …) are
// allocated but not recursed into; their own runtime semantics would
// conflict with naive zero-filling and CEL handles them specially
// already.
func FillNilMessages(m proto.Message) {
	if m == nil {
		return
	}
	fillReflect(m.ProtoReflect())
}

func fillReflect(msg protoreflect.Message) {
	if !msg.IsValid() {
		return
	}
	fields := msg.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.ContainingOneof() != nil {
			continue
		}
		switch {
		case fd.IsMap():
			if fd.MapValue().Kind() != protoreflect.MessageKind {
				continue
			}
			if !msg.Has(fd) {
				continue
			}
			msg.Get(fd).Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
				fillReflect(v.Message())
				return true
			})
		case fd.IsList():
			if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
				continue
			}
			list := msg.Get(fd).List()
			for j := range list.Len() {
				fillReflect(list.Get(j).Message())
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			sub := msg.Mutable(fd).Message()
			if !isWellKnownType(sub.Descriptor()) {
				fillReflect(sub)
			}
		}
	}
}

// isWellKnownType reports whether the descriptor names a type from the
// google.protobuf.* package (Struct, Value, Timestamp, etc.). These
// types have their own runtime semantics and aren't safe to walk
// blindly; their parent fields still get allocated, just not recursed.
func isWellKnownType(d protoreflect.MessageDescriptor) bool {
	return strings.HasPrefix(string(d.FullName()), "google.protobuf.")
}
