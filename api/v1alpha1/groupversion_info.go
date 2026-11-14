/*
Copyright 2026 Tessarac, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package v1alpha1 contains the natterjack.io/v1alpha1 API: EgressPool,
// EgressPolicy and ClusterEgressPolicy.
//
// +kubebuilder:object:generate=true
// +groupName=natterjack.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Group is the API group, and the prefix of every tag and label Natterjack reads.
const Group = "natterjack.io"

var (
	// GroupVersion is the group and version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: Group, Version: "v1alpha1"}

	// SchemeBuilder adds the types in this package to a scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this package to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&EgressPool{}, &EgressPoolList{},
		&EgressPolicy{}, &EgressPolicyList{},
		&ClusterEgressPolicy{}, &ClusterEgressPolicyList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
