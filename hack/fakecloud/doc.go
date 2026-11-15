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

// Command fakecloud stands in for EC2 and the internet in the kind
// data-path tests: the controller's AWS provider talks to it as it would
// to EC2, and attaching a slot moves a real interface into the node, so
// gateway traffic takes the path it takes on AWS. It runs in a privileged
// container on the kind network that shares the host's process namespace.
// See hack/datapath-e2e.sh.
package main
