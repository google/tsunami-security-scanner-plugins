// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v3.21.12
// source: action_utils.proto

package templated_plugin_go_proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SleepUtilityAction struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The duration of the sleep in milliseconds.
	DurationMs    int64 `protobuf:"varint,1,opt,name=duration_ms,json=durationMs,proto3" json:"duration_ms,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SleepUtilityAction) Reset() {
	*x = SleepUtilityAction{}
	mi := &file_action_utils_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SleepUtilityAction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SleepUtilityAction) ProtoMessage() {}

func (x *SleepUtilityAction) ProtoReflect() protoreflect.Message {
	mi := &file_action_utils_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SleepUtilityAction.ProtoReflect.Descriptor instead.
func (*SleepUtilityAction) Descriptor() ([]byte, []int) {
	return file_action_utils_proto_rawDescGZIP(), []int{0}
}

func (x *SleepUtilityAction) GetDurationMs() int64 {
	if x != nil {
		return x.DurationMs
	}
	return 0
}

// Set of utilities that can be used by plugins.
type UtilityAction struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Action:
	//
	//	*UtilityAction_Sleep
	Action        isUtilityAction_Action `protobuf_oneof:"action"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *UtilityAction) Reset() {
	*x = UtilityAction{}
	mi := &file_action_utils_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UtilityAction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UtilityAction) ProtoMessage() {}

func (x *UtilityAction) ProtoReflect() protoreflect.Message {
	mi := &file_action_utils_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UtilityAction.ProtoReflect.Descriptor instead.
func (*UtilityAction) Descriptor() ([]byte, []int) {
	return file_action_utils_proto_rawDescGZIP(), []int{1}
}

func (x *UtilityAction) GetAction() isUtilityAction_Action {
	if x != nil {
		return x.Action
	}
	return nil
}

func (x *UtilityAction) GetSleep() *SleepUtilityAction {
	if x != nil {
		if x, ok := x.Action.(*UtilityAction_Sleep); ok {
			return x.Sleep
		}
	}
	return nil
}

type isUtilityAction_Action interface {
	isUtilityAction_Action()
}

type UtilityAction_Sleep struct {
	Sleep *SleepUtilityAction `protobuf:"bytes,1,opt,name=sleep,proto3,oneof"`
}

func (*UtilityAction_Sleep) isUtilityAction_Action() {}

var File_action_utils_proto protoreflect.FileDescriptor

var file_action_utils_proto_rawDesc = string([]byte{
	0x0a, 0x12, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x75, 0x74, 0x69, 0x6c, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x74, 0x73, 0x75, 0x6e, 0x61, 0x6d, 0x69, 0x5f, 0x74, 0x65,
	0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74, 0x6f, 0x72,
	0x22, 0x35, 0x0a, 0x12, 0x53, 0x6c, 0x65, 0x65, 0x70, 0x55, 0x74, 0x69, 0x6c, 0x69, 0x74, 0x79,
	0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x5f, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x64, 0x75, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x73, 0x22, 0x61, 0x0a, 0x0d, 0x55, 0x74, 0x69, 0x6c, 0x69,
	0x74, 0x79, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x46, 0x0a, 0x05, 0x73, 0x6c, 0x65, 0x65,
	0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x74, 0x73, 0x75, 0x6e, 0x61, 0x6d,
	0x69, 0x5f, 0x74, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x64, 0x65, 0x74, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x2e, 0x53, 0x6c, 0x65, 0x65, 0x70, 0x55, 0x74, 0x69, 0x6c, 0x69, 0x74,
	0x79, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x00, 0x52, 0x05, 0x73, 0x6c, 0x65, 0x65, 0x70,
	0x42, 0x08, 0x0a, 0x06, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x9c, 0x01, 0x0a, 0x28, 0x63,
	0x6f, 0x6d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x74, 0x73, 0x75, 0x6e, 0x61, 0x6d,
	0x69, 0x2e, 0x74, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x70, 0x6c, 0x75, 0x67, 0x69,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x6e, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x74, 0x73, 0x75,
	0x6e, 0x61, 0x6d, 0x69, 0x2d, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2d, 0x73, 0x63,
	0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2f, 0x74, 0x65,
	0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x2f, 0x74, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65,
	0x64, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x74, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e,
	0x5f, 0x67, 0x6f, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
})

var (
	file_action_utils_proto_rawDescOnce sync.Once
	file_action_utils_proto_rawDescData []byte
)

func file_action_utils_proto_rawDescGZIP() []byte {
	file_action_utils_proto_rawDescOnce.Do(func() {
		file_action_utils_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_action_utils_proto_rawDesc), len(file_action_utils_proto_rawDesc)))
	})
	return file_action_utils_proto_rawDescData
}

var file_action_utils_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_action_utils_proto_goTypes = []any{
	(*SleepUtilityAction)(nil), // 0: tsunami_templated_detector.SleepUtilityAction
	(*UtilityAction)(nil),      // 1: tsunami_templated_detector.UtilityAction
}
var file_action_utils_proto_depIdxs = []int32{
	0, // 0: tsunami_templated_detector.UtilityAction.sleep:type_name -> tsunami_templated_detector.SleepUtilityAction
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_action_utils_proto_init() }
func file_action_utils_proto_init() {
	if File_action_utils_proto != nil {
		return
	}
	file_action_utils_proto_msgTypes[1].OneofWrappers = []any{
		(*UtilityAction_Sleep)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_action_utils_proto_rawDesc), len(file_action_utils_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_action_utils_proto_goTypes,
		DependencyIndexes: file_action_utils_proto_depIdxs,
		MessageInfos:      file_action_utils_proto_msgTypes,
	}.Build()
	File_action_utils_proto = out.File
	file_action_utils_proto_goTypes = nil
	file_action_utils_proto_depIdxs = nil
}
